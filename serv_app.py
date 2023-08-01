import base64
from io import BytesIO

import cv2
import numpy as np
import streamlit as st
import os

from PIL import Image
from streamlit import runtime
from streamlit.runtime.scriptrunner import get_script_run_ctx

from models.managers import CameraManager


def get_remote_ip() -> str:
    try:
        ctx = get_script_run_ctx()
        if ctx is None:
            return None
        session_info = runtime.get_instance().get_client(ctx.session_id)
        if session_info is None:
            return None
    except Exception as e:
        return None

    return session_info.request


def add_padding(base64_string):
    missing_padding = 4 - len(base64_string) % 4
    return base64_string + '=' * missing_padding


def show_image_from_database(image_b64):
    image_b64 = add_padding(image_b64)
    image_data = base64.b64decode(image_b64)
    try:
        image = Image.open(BytesIO(image_data))
        st.image(image, use_column_width=True)
    except Exception as e:
        st.error("Error: Unable to display the image.")
        st.write(str(e))


def show_images(images):
    if isinstance(images, list):
        # If the input is a list of images, show them one by one
        for img in images:
            show_images(img)
    elif isinstance(images, np.ndarray):
        # If the input is a numpy array, convert it to an Image object and display it
        image = Image.fromarray(images)
        st.image(image, use_column_width=True)
    elif isinstance(images, BytesIO):
        # If the input is BytesIO, open it as an Image and display it
        image = Image.open(images)
        st.image(image, use_column_width=True)
    elif isinstance(images, str):
        # If the input is a string, check if it's a URL, local file path, or SVG XML string
        if images.startswith("<svg") and images.endswith("</svg>"):
            # If the input is an SVG XML string, display it as an SVG image
            st.image(images, use_column_width=True, format="svg")
        elif images.startswith("http://") or images.startswith("https://") or images.startswith("ftp://"):
            # If the input is a URL, display the image from the URL
            st.image(images, use_column_width=True)
        else:
            # Assume the input is a local file path, open it as an Image and display it
            image = Image.open(images)
            st.image(image, use_column_width=True)
    else:
        st.error("Invalid input format. Please provide an image in one of the accepted formats.")


def main():
    db_connector = CameraManager()

    st.title("Brazil open cameras")
    user_info = get_remote_ip()
    ua = dict(user_info.headers).get('User-Agent')
    user_ip = user_info.remote_ip
    st.write(f"You are: {ua} at {user_ip}")

    user_input = st.text_input("Add your shodan key to perform a live search", "")

    if user_input:
        ...
        # cams_found = thread_add_cameras_on_db(user_input)
        # st.write(cams_found)

    folder_path = 'frames'
    current_full_path = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(current_full_path, folder_path)
    cams = db_connector.get_all_images_from_db()

    if not cams:
        st.error("No images found in the selected folder.")
        return

    ips_ports = set()
    for c in cams:
        ip, port = c.ip, c.port
        ips_ports.add((ip, port))
        cidade = c.city
        country = c.country_name
        image = cv2.imdecode(np.frombuffer(bytes(c.image_b64), np.uint8), -1)
        image = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        cv2.imwrite(f"{folder_path}/{ip}_{port}.jpg", image)


if __name__ == "__main__":
    main()
