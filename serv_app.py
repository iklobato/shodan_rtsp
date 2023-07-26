import streamlit as st
import os

from streamlit import runtime
from streamlit.runtime.scriptrunner import get_script_run_ctx

from rtsp_scanner import DatabaseConnector, thread_add_cameras_on_db, db


def list_images_in_folder(folder_path):
    image_extensions = (".png", ".jpg", ".jpeg", ".gif")
    image_files = [file for file in os.listdir(folder_path) if file.lower().endswith(image_extensions)]
    return image_files


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

    return session_info.request.remote_ip


def main():

    st.title("Brazil open cameras")
    # user_ip = get_remote_ip()
    # st.write(f"Your IP: {user_ip}")
    # proint = st.empty()
    # print(user_ip)

    user_input = st.text_input("Add your shodan key to perform a live search", "")

    if user_input:
        cams_found = thread_add_cameras_on_db(user_input)
        st.write(cams_found)

    folder_path = 'frames'
    current_full_path = os.path.dirname(os.path.abspath(__file__))
    folder_path = os.path.join(current_full_path, folder_path)
    image_files = list_images_in_folder(folder_path)

    if not image_files:
        st.error("No images found in the selected folder.")
        return

    for im in image_files:
        ip, port = im.split('_')
        port = port.split('.')[0]
        cam_info = db.search_on_db(ip, port)
        if not cam_info:
            continue
        cidade = cam_info[0][6]
        st.image(os.path.join(folder_path, im), use_column_width=True, caption=cidade)


if __name__ == "__main__":
    main()
