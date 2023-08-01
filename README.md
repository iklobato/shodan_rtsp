<img src="https://github.com/henriqueblobato/shodan_rtsp/assets/18133417/b2fd3f57-89c8-454f-9afc-e28d040f91dc" width="200"/>

# Camera Scanner

The Camera Scanner is a Python command-line tool that allows you to search for and test cameras on various sources like Shodan and through Nmap scanning. It is designed to help identify cameras that may be publicly accessible or vulnerable to potential security issues.

### Streamlit deployment
![Screen Shot 2023-07-26 at 05 51 08](https://github.com/henriqueblobato/shodan_rtsp/assets/18133417/77ad3b8d-97ac-439e-b254-1fe9679760d2)
![Screen Shot 2023-07-26 at 05 52 38](https://github.com/henriqueblobato/shodan_rtsp/assets/18133417/e38b85db-fff7-42d0-93f9-460016828490)

### Live application
You can check the app here
https://shodanrtsp-oxee2uql3oo.streamlit.app/

## Installation

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/henriqueblobato/shodan_rtsp
   cd shodan_rtsp
   ```

2. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To run the Camera Scanner, use the following command-line arguments:

```bash
python main.py [--start_search | --start_check | --start_nmap] [--config CONFIG] [-v]
```

### Command-line Arguments:

- `--start_search`: Initiates a search for cameras using Shodan.
- `--start_check`: Starts testing cameras on a database.
- `--start_nmap`: Starts Nmap scan to discover cameras on a specific IP range.

### Options:

- `--config CONFIG`: Specifies the path to the configuration file. Default is `config.ini`.
- `-v`, `--verbose`: Enables verbose mode, providing more detailed output.

## Configuration

The `config.ini` file contains the necessary configurations for Shodan and Nmap tasks. Make sure to provide the required values in the following format:

```ini
[shodan_config]
shodan_key = <your_shodan_api_key>

[checkers_config]
wordlist_users = wordlists/users_small.txt
wordlist_passwords = wordlists/passwords_small.txt
wordlist_rtsp_urls = wordlists/rtsp_urls_small.txt
randomize = true

[nmap_config]
ip_range = 200.128.0.0/24
```

Ensure you replace `<your_shodan_api_key>` with your actual Shodan API key.

## Example

Here's an example of how to use the Camera Scanner:

1. To search for cameras on Shodan:

   ```bash
   python camera_scanner.py --start_search --config my_config.ini -v
   ```

2. To test cameras on a database:

   ```bash
   python camera_scanner.py --start_check --config my_config.ini
   ```

3. To perform an Nmap scan on a specific IP range:

   ```bash
   python camera_scanner.py --start_nmap --config my_config.ini
   ```

## Disclaimer

The Camera Scanner is intended for educational and informational purposes only. It should not be used for any illegal activities or to access unauthorized devices. The developers of this tool are not responsible for any misuse or damages caused by its use.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

### TODO
- General:
  - [ ] Add log level as an argument as -v1, -v2 and -v 3 
  - [ ] Make the script more modular, solid concepts, and better code.
  - [ ] Reduce the number of arguments and make the script more user-friendly.
  - [ ] SOLID principles to make the code more maintainable.
- Local changes:
  - [x] Add more cameras to the local database.
  - [x] Add more usernames and passwords to the files.
  - [x] Add more RTSP URLs to the file.
- Database
  - [ ] Database class creation, to deal with the database.
  - [ ] Database class encapsulate the database queries.
  - [ ] Make database class thread safe and add a lock to it.
- Usability:
  - [ ] Make it into a python package and upload it to PyPI.
  - [ ] Create a CLI for the script.
- Architecture:
  - [ ] Dockerize the application.
  - [ ] Setup architecture to run the application in the cloud.
- Integrations:
  - [ ] Add integration with Telegram.
  - [ ] Add integration with Discord.
  - [ ] Add integration with Slack.
  - [ ] Add integration with Twitter.
- Interface
  - [ ] Create a web interface for the application.
    - Fast options to use: streamlit
  - [ ] Users with login managed by the application.
  - [ ] Users can add their own cameras to the database.
