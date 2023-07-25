
# RTSP Scanner
This is a Python script that allows you to scan for cameras using the Real Time Streaming Protocol (RTSP) on Shodan and test them against a local database. The script offers options to customize the scanning process according to your preferences.
It will also save the results of the scan in a local database, so that you can test the cameras later without having to scan for them again.
This local database its used to avoid scanning the same cameras over and over again, and also to be used to check for cameras credentials that you already have.

### Requirements installation
```bash
pip install -r requirements.txt
```

### Environment file
Edit the `.env` file and add your Shodan API key and database password.
```bash
SHODAN_KEY=<your_shodan_api_key>
```

### Usage
To use the RTSP Scanner, run the following command:
```bash
python rtsp_scanner.py [--start_search | --start_check] \
[--threads THREADS] \
[--test_sleep TEST_SLEEP] \
[--db_sleep DB_SLEEP] \
[--users USERS_FILE] \
[--passwords PASSWORDS_FILE] \
[--rtsp_urls RTSP_URLS_FILE] \
[--random] \
[--db_name DB_NAME] \
[-v]
```

### Arguments
- `--start_search` Start searching for cameras on Shodan. (Note: This argument is mutually exclusive with `--start_check` and is required.)
- `--start_check` Start testing cameras on the local database. (Note: This argument is mutually exclusive with `--start_search` and is required.)
- `--threads THREADS`: Number of threads to use for checking cameras. (Default: 1)
- `--test_sleep TEST_SLEEP` Test cameras in the local database every N seconds. (Default: 30)
- `--db_sleep DB_SLEEP` Update the local database with Shodan results every N seconds. (Default: 86400, i.e., 1 day)
- `--users USERS_FILE` Path to the file containing user names. (Default: 'users_small.txt')
- `--passwords PASSWORDS_FILE` Path to the file containing passwords. (Default: 'passwords_small.txt')
- `--rtsp_urls RTSP_URLS_FILE`
  - Path to the file containing RTSP URLs. (Default: 'rtsp_urls_small.txt')
  - The format of the file should be as follows:
    ```
    rtsp://{}:{}@{}:{}/media/video2
    ...
    ```
    - The first `{}` will be replaced with a random user name from the `--users` file.
    - The second `{}` will be replaced with a random password from the `--passwords` file.
    - The third `{}` will be replaced with the IP address of the camera found at Shodan.
    - The fourth `{}` will be replaced with the port of the camera found at Shodan.
- `--random` Randomize users, passwords, and RTSP URLs. (Default: True)
- `--db_name DB_NAME` Name of the local database. (Default: 'rtsp_scanner.db')
- `-v`, `--verbose` Enable verbose mode.

### TODO
- [x] Add more cameras to the local database.
- [x] Add more usernames and passwords to the files.
- [x] Add more RTSP URLs to the file.
- [ ] Database class creation, to deal with the database.
- [ ] Database class encapsulate the database queries.
- [ ] Make it into a python package and upload it to PyPI.
- [ ] Dockerize the application.
- [ ] Setup architecture to run the application in the cloud.