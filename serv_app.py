import os

import cv2
import numpy as np
import streamlit as st
from streamlit import runtime
from streamlit.runtime.scriptrunner import get_script_run_ctx

from models.managers import CameraRepository


def get_remote_ip():
    try:
        ctx = get_script_run_ctx()
        if ctx is None:
            return None
        return runtime.get_instance().get_client(ctx.session_id)
    except Exception:
        return None


def main():
    repository = CameraRepository()

    st.title("Brazil open cameras")
    user_info = get_remote_ip()
    if user_info is not None:
        ua = dict(user_info.request.headers).get("User-Agent")
        st.write(f"You are: {ua} at {user_info.request.remote_ip}")

    folder_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frames")
    os.makedirs(folder_path, exist_ok=True)
    cams = repository.get_active()

    if not cams:
        st.error("No images found in the selected folder.")
        return

    for camera in cams:
        image = cv2.imdecode(np.frombuffer(bytes(camera.image_b64), np.uint8), -1)
        image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        cv2.imwrite(f"{folder_path}/{camera.ip}_{camera.port}.jpg", image)


if __name__ == "__main__":
    main()
