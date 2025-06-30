# SPDX-License-Identifier: GPL-2.0
# Copyright (C) 2025 Bardia Moshiri <bardia@furilabs.com>

import gi
import os
import threading
import tempfile
import time
import numpy as np
import weakref
from typing import List, Dict, Optional, Callable
from PIL import Image
import zbar

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
gi.require_version('Gst', '1.0')
gi.require_version('GstVideo', '1.0')
from gi.repository import Gst, GstVideo, GLib, GObject, Gtk, Adw

Gst.init(None)

class CameraDevice:
    def __init__(self, index: int, path: str, name: str, object_id: Optional[str] = None):
        self.index = index
        self.path = path
        self.name = name
        self.object_id = object_id

    def __str__(self):
        return f"{self.name} ({self.path})"

class QRScanResult:
    def __init__(self, data: str, format_type: str, bbox: tuple = None):
        self.data = data
        self.format_type = format_type
        self.bbox = bbox

    def is_otpauth(self) -> bool:
        return self.data.startswith('otpauth://')

class CameraQRScanner:
    def __init__(self):
        self.pipeline = None
        self.appsink = None
        self.viewfinder_sink = None
        self.cameras = []
        self.current_camera_index = 0
        self.is_scanning = False
        self.scan_callback = None
        self.last_scan_time = 0
        self.scan_interval = 1.0
        self.scan_thread = None
        self.latest_frame = None
        self.frame_lock = threading.Lock()
        self.frame_counter = 0
        self.max_frames_in_memory = 2
        self.discover_cameras()

    def __del__(self):
        self.cleanup()

    def cleanup(self):
        self.stop_scanning()
        with self.frame_lock:
            self.latest_frame = None

    def discover_cameras(self) -> List[CameraDevice]:
        self.cameras = []

        try:
            monitor = Gst.DeviceMonitor()
            monitor.add_filter("Video/Source", None)

            if not monitor.start():
                print("Failed to start GStreamer device monitor")
                return self.cameras

            devices = monitor.get_devices()
            camera_index = 0

            for device in devices:
                try:
                    device_name = device.get_display_name()
                    caps = device.get_caps()

                    # Check if this has Video/Source capability
                    has_video_source = False
                    for i in range(caps.get_size()):
                        structure = caps.get_structure(i)
                        if structure.get_name().startswith("video/"):
                            has_video_source = True
                            break

                    if not has_video_source:
                        continue

                    # Get PipeWire object ID for targeting
                    props = device.get_properties()
                    object_id = None

                    object_serial_int = props.get_int("object.serial")
                    if object_serial_int[0]:  # get_int returns (success, value)
                        object_id = str(object_serial_int[1])
                        print(f"Found object.serial: {object_id} for device: {device_name}")

                    if not object_id:
                        print(f"No object ID found for device: {device_name}")
                        continue

                    device_path = f"pipewire:{object_id}"

                    camera = CameraDevice(camera_index, device_path, device_name, object_id)
                    self.cameras.append(camera)
                    camera_index += 1

                    print(f"Found camera: {device_name} - Object ID: {object_id}")
                except Exception as e:
                    print(f"Error processing camera device: {e}")
                    continue

            monitor.stop()

            print(f"Discovered {len(self.cameras)} camera devices")
        except Exception as e:
            print(f"Error discovering cameras: {e}")
        return self.cameras

    def get_available_cameras(self) -> List[CameraDevice]:
        return self.cameras.copy()

    def get_current_camera(self) -> Optional[CameraDevice]:
        if 0 <= self.current_camera_index < len(self.cameras):
            return self.cameras[self.current_camera_index]
        return None

    def get_viewfinder_widget(self):
        if self.viewfinder_sink:
            try:
                # Get the gtk4paintablesink from inside the glsinkbin
                gtk4_sink = self.viewfinder_sink.get_property("sink")
                if not gtk4_sink:
                    print("Failed to get gtk4paintablesink from glsinkbin")
                    return None

                # Get the paintable from the gtk4paintablesink
                paintable = gtk4_sink.get_property("paintable")
                if not paintable:
                    print("No paintable available from gtk4paintablesink")
                    return None

                clamp = Adw.Clamp()
                clamp.set_maximum_size(200)
                clamp.set_tightening_threshold(150)

                aspect_frame = Gtk.AspectFrame()
                aspect_frame.set_ratio(9.0 / 16.0)
                aspect_frame.set_obey_child(False)

                # Create the picture widget with the paintable
                picture = Gtk.Picture.new_for_paintable(paintable)
                picture.set_content_fit(Gtk.ContentFit.COVER)
                picture.set_can_shrink(True)

                # Put picture in aspect frame, then in clamp
                aspect_frame.set_child(picture)
                clamp.set_child(aspect_frame)

                return clamp
            except Exception as e:
                print(f"Error getting viewfinder widget: {e}")
        return None

    def switch_camera(self) -> bool:
        if len(self.cameras) <= 1:
            return False

        was_scanning = self.is_scanning
        if was_scanning:
            self.stop_scanning()

        self.current_camera_index = (self.current_camera_index + 1) % len(self.cameras)

        if was_scanning:
            return self.start_scanning(self.scan_callback)

        return True

    def create_pipeline(self, camera_index: int = None) -> bool:
        if camera_index is None:
            camera_index = self.current_camera_index

        if camera_index >= len(self.cameras):
            print("Invalid camera index")
            return False

        camera = self.cameras[camera_index]

        try:
            if not camera.object_id:
                print(f"No object ID available for camera: {camera.name}")
                return False

            pipeline_desc = (
                f"pipewiresrc name=source target-object={camera.object_id} ! "
                "videoconvert ! videoscale ! video/x-raw,width=640,height=480 ! tee name=t ! "
                "queue ! videoscale ! "
                "glsinkbin sink=\"gtk4paintablesink name=gtk_sink\" name=sink_bin "
                "t. ! queue leaky=2 max-size-buffers=1 ! videoscale ! "
                "video/x-raw,width=320,height=240 ! videoconvert ! video/x-raw,format=RGB ! "
                "appsink name=app_sink max-buffers=1 drop=true emit-signals=true sync=false"
            )

            print(f"Creating pipeline: {pipeline_desc}")
            self.pipeline = Gst.parse_launch(pipeline_desc)

            if not self.pipeline:
                print("Failed to create pipeline")
                return False

            # Get appsink
            self.appsink = self.pipeline.get_by_name("app_sink")
            if not self.appsink:
                print("Failed to get appsink element")
                return False

            self.appsink.connect("new-sample", self._on_new_sample)

            # Get the glsinkbin to access the gtk4paintablesink
            self.viewfinder_sink = self.pipeline.get_by_name("sink_bin")
            if not self.viewfinder_sink:
                print("Failed to get glsinkbin element")
                return False

            print("Successfully created pipeline")
            return True
        except Exception as e:
            print(f"Error creating pipeline: {e}")
            return False

    def _on_new_sample(self, appsink):
        try:
            # Skip frames more aggressively if we're already processing one
            with self.frame_lock:
                if self.latest_frame is not None:
                    return Gst.FlowReturn.OK

            # Skip most frames to reduce CPU/memory usage
            self.frame_counter += 1
            if self.frame_counter % 10 != 0:
                return Gst.FlowReturn.OK

            sample = appsink.emit("pull-sample")
            if sample:
                buffer = sample.get_buffer()
                caps = sample.get_caps()

                structure = caps.get_structure(0)
                width = structure.get_int('width')[1]
                height = structure.get_int('height')[1]

                success, mapinfo = buffer.map(Gst.MapFlags.READ)
                if success:
                    try:
                        frame_data = np.frombuffer(mapinfo.data, dtype=np.uint8)
                        frame_data = frame_data.reshape((height, width, 3))

                        with self.frame_lock:
                            # Only store if we don't already have a frame
                            if self.latest_frame is None:
                                self.latest_frame = frame_data
                    finally:
                        buffer.unmap(mapinfo)
        except Exception as e:
            print(f"Error processing frame: {e}")
        return Gst.FlowReturn.OK

    def _scan_worker(self):
        print("Starting QR scan worker thread")

        while self.is_scanning:
            try:
                current_time = time.time()

                if current_time - self.last_scan_time < self.scan_interval:
                    time.sleep(0.2)
                    continue

                frame = None
                with self.frame_lock:
                    if self.latest_frame is not None:
                        frame = self.latest_frame
                        self.latest_frame = None

                if frame is not None:
                    try:
                        qr_results = self._detect_qr_codes(frame)

                        if qr_results:
                            print(f"Found {len(qr_results)} QR code(s)")
                            for result in qr_results:
                                print(f"  QR: {result.data[:50]}...")
                                if result.is_otpauth() and self.scan_callback:
                                    GLib.idle_add(self.scan_callback, result)
                                    return
                        self.last_scan_time = current_time
                    finally:
                        # Ensure frame is deleted to free memory
                        del frame
                else:
                    time.sleep(0.2)
            except Exception as e:
                print(f"Error in scan worker: {e}")
                time.sleep(1)
        print("QR scan worker thread ended")

    def _detect_qr_codes(self, frame: np.ndarray) -> List[QRScanResult]:
        try:
            if len(frame.shape) == 3:
                gray_array = np.dot(frame[...,:3], [0.2989, 0.5870, 0.1140]).astype(np.uint8)
            else:
                gray_array = frame

            scanner = zbar.ImageScanner()
            scanner.parse_config('enable')

            height, width = gray_array.shape
            raw_data = gray_array.tobytes()

            zbar_image = zbar.Image(width, height, 'Y800', raw_data)

            result = scanner.scan(zbar_image)

            results = []
            for symbol in zbar_image:
                try:
                    if isinstance(symbol.data, bytes):
                        data = symbol.data.decode('utf-8')
                    else:
                        data = str(symbol.data)

                    format_type = str(symbol.type)

                    bbox = None
                    if hasattr(symbol, 'location') and symbol.location:
                        location = symbol.location
                        xs = [point[0] for point in location]
                        ys = [point[1] for point in location]
                        x_min, x_max = min(xs), max(xs)
                        y_min, y_max = min(ys), max(ys)
                        bbox = (x_min, y_min, x_max - x_min, y_max - y_min)

                    qr_result = QRScanResult(data, format_type, bbox)
                    results.append(qr_result)
                except (UnicodeDecodeError, AttributeError) as e:
                    print(f"Failed to decode QR code data: {e}")
                    continue

            # Clean up scanner and image explicitly to not hog memory
            del scanner
            del zbar_image

            return results
        except Exception as e:
            print(f"Error detecting QR codes: {e}")
            return []

    def scan_image_file(self, filepath: str) -> List[QRScanResult]:
        try:
            pil_image = Image.open(filepath)

            if pil_image.mode != 'RGB':
                pil_image = pil_image.convert('RGB')

            frame = np.array(pil_image)

            return self._detect_qr_codes(frame)
        except Exception as e:
            print(f"Error scanning image file: {e}")
            return []

    def start_scanning(self, callback: Callable[[QRScanResult], None]) -> bool:
        if self.is_scanning:
            print("Already scanning")
            return True

        if not self.cameras:
            print("No cameras available")
            return False

        self.scan_callback = callback

        if not self.create_pipeline():
            print("Failed to create camera pipeline")
            return False

        try:
            ret = self.pipeline.set_state(Gst.State.PLAYING)
            if ret == Gst.StateChangeReturn.FAILURE:
                print("Failed to start camera pipeline")
                bus = self.pipeline.get_bus()
                if bus:
                    msg = bus.timed_pop_filtered(Gst.CLOCK_TIME_NONE, Gst.MessageType.ERROR)
                    if msg:
                        err, debug = msg.parse_error()
                        print(f"GStreamer error: {err.message}, {debug}")
                return False

            self.is_scanning = True

            self.scan_thread = threading.Thread(target=self._scan_worker, daemon=True)
            self.scan_thread.start()

            current_camera = self.get_current_camera()
            print(f"Started QR scanning with camera: {current_camera}")
            return True
        except Exception as e:
            print(f"Error starting camera: {e}")
            return False

    def stop_scanning(self):
        if not self.is_scanning:
            return

        print("Stopping QR scanner")
        self.is_scanning = False

        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=2)

        if self.pipeline:
            try:
                self.pipeline.set_state(Gst.State.NULL)
                self.pipeline = None
                self.appsink = None
                self.viewfinder_sink = None
            except Exception as e:
                print(f"Error stopping pipeline: {e}")

        # Clear any remaining frames
        with self.frame_lock:
            self.latest_frame = None

        print("QR scanner stopped")

def create_qr_scanner() -> CameraQRScanner:
    return CameraQRScanner()

def scan_qr_from_file(filepath: str) -> List[QRScanResult]:
    scanner = CameraQRScanner()
    try:
        return scanner.scan_image_file(filepath)
    finally:
        scanner.cleanup()

def get_available_cameras() -> List[CameraDevice]:
    scanner = CameraQRScanner()
    try:
        return scanner.get_available_cameras()
    finally:
        scanner.cleanup()
