#!/usr/bin/python3
import requests
import sys
import json
import argparse
import time


class Sast:
    def __init__(self, server_name):
        self.server_name = server_name
        self.token = None  # Set through get_auth_token

    def set_auth_token(self, username, password):
        api = '/cxrestapi/auth/identity/connect/token'
        final_url = self.server_name + api
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        post_fields = {
            "username": username,
            "password": password,
            "grant_type": 'password',
            "scope": 'sast_rest_api',
            "client_id": 'resource_owner_client',
            "client_secret": '014DF517-39D1-4453-B7B3-9930C563627C',
        }
        response = requests.post(final_url,
                                 data=post_fields,
                                 headers=headers)
        json_obj = json.loads(response.text)
        try:
            self.token = json_obj['access_token']
        except KeyError:
            print(json_obj)
            sys.exit(1)

    def get_project_id(self, project_name):
        api = '/cxrestapi/projects'
        final_url = self.server_name + api
        headers = {"Content-Type": "application/json;v=2.0",
                   "Accept": "application/json",
                   "Authorization": "Bearer " + self.token}
        response = requests.get(final_url, headers=headers).json()
        for project_info in response:
            if project_info['name'] == project_name:
                return project_info['id']

    def get_latest_scan_id(self, project_id):
        api = '/cxrestapi/sast/scans'
        final_url = self.server_name + api
        headers = {"Accept": "application/json;v=1.0",
                   "Authorization": "Bearer " + self.token}
        get_fields = {
            "last": '1',
            "scanStatus": "Finished",
            "projectId": project_id
        }
        response = requests.get(final_url, params=get_fields, headers=headers).json()
        return response[0]['id']

    def get_report_id(self, scan_id, report_format):
        api = "/cxrestapi/reports/sastScan"
        final_url = self.server_name + api
        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "application/json",
                   "Authorization": "Bearer " + self.token}
        post_fields = {
            "reportType": {report_format},
            "scanId": scan_id}
        response = requests.post(final_url, data=post_fields, headers=headers).json()
        try:
            report_id = response["reportId"]
        except KeyError:
            print(response)
            sys.exit(1)
        return report_id

    def get_report_status(self, report_id):
        api = f"/cxrestapi/reports/sastScan/{report_id}/status"
        final_url = self.server_name + api
        headers = {"Accept": "application/json;v=1.0",
                   "Authorization": "Bearer " + self.token}
        response = requests.get(final_url, headers=headers).json()
        return response['status']['value']

    def save_report(self, file_path, report_id, project_name, report_format):
        api = f"/cxrestapi/reports/sastScan/{report_id}"
        final_url = self.server_name + api
        headers = {"Accept": "application/json",
                   "Authorization": "Bearer " + self.token}
        response = requests.get(final_url, headers=headers)
        open(f"{file_path}/{project_name}_report.{report_format}", 'wb').write(response.content)


def main():
    # Initialize
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    # Example string variable
    parser.add_argument('-u', '--username', dest="username", help='Checkmarx SAST REST API username',
                        default=argparse.SUPPRESS, required=True)
    parser.add_argument('-p', '--password', dest="password", help='Checkmarx SAST REST API password',
                        default=argparse.SUPPRESS, required=True)
    parser.add_argument('-d', '--save-path', dest="save_path", help='Path where SAST reports files will be saved',
                        default=argparse.SUPPRESS, required=True)
    parser.add_argument('-n', '--project-name', dest="project_name", help='Checkmarx SAST project name',
                        default=argparse.SUPPRESS, required=True)
    parser.add_argument('-t', '--timeout', dest="timeout", default="60",
                        help='Timeout for waiting server answer (in seconds)')
    parser.add_argument('-s', '--server-name', dest='server_name',
                        default='https://sast-server.domain.local:8443',
                        help='Checkmarx SAST server (http(s)://server.local:8443')
    parser.add_argument('-r', '--report-formats', dest='report_formats', default=['pdf', 'csv', 'xml'],
                        help='Report formats to be generated. Supported: PDF, RTF, CSV, XML', nargs='+')

    # Show help if no arguments provided
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Load args as variables
    args = parser.parse_args()
    # Setup variables through args
    username = args.username
    password = args.password
    file_save_path = args.save_path
    project_name = args.project_name
    timeout = int(args.timeout)
    server_name = args.server_name
    report_formats = args.report_formats

    sast = Sast(server_name)  # Get new Sast instance
    sast.set_auth_token(username, password)  # Setup access token
    project_id = sast.get_project_id(project_name)
    scan_id = sast.get_latest_scan_id(project_id)

    for report_format in report_formats:
        report_id = sast.get_report_id(scan_id, report_format)
        time_count = 0
        is_report_created = False
        while time_count < timeout:
            time.sleep(5)
            time_count += 5
            report_status = sast.get_report_status(report_id)
            if report_status == 'Created':
                sast.save_report(file_save_path, report_id, project_name, report_format)
                print(f'Report {report_format} created')
                is_report_created = True
                break
            else:
                pass
        if not is_report_created:
            print('Generation of report - timed out')
            sys.exit(1)


if __name__ == "__main__":
    main()
