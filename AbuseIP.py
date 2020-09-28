# Script by https://github.com/chugalde
#
import requests
import json
import csv
import argparse

# CONSTANTS
IPLISTFILE = 'list.txt'


def create_arguments():
    parser = argparse.ArgumentParser(add_help=False)
    parser._action_groups.pop()
    required = parser.add_argument_group('required arguments')
    optional = parser.add_argument_group('optional arguments')
    # Add back help
    optional.add_argument(
        '-h',
        '--help',
        action='help',
        help='show this help message and exit'
    )

    # Optional
    optional.add_argument(
        '-o', '--output', help='Output file path', default='results.csv')
    optional.add_argument(
        '--ips', help='Define couple of IPs to search, delimited by commas', nargs='+')
    optional.add_argument(
        '-d', '--days', help='Determines how far back in time to go to fetch reports', type=int, default=365)

    # Required
    required.add_argument(
        '-k', '--key', help='API Key from AbuseIPDB', required=True)
    return parser.parse_args()


def get_ips():
    with open(IPLISTFILE, 'r') as file:
        ipList = file.read().splitlines()
    return ipList


def write_output(outputFile, outputData, action):
    with open(outputFile, action, newline='') as file:
        writer = csv.writer(file)
        writer.writerows(outputData)


def request_ipdb(apiKey, ip, days):
    # URL de la API
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {  # Aquí se pueden agregar filtros.
        'ipAddress': ip,
        'maxAgeInDays': days,  # Buscar con este máximo de días.
    }

    headers = {
        'Accept': 'application/json',
        'Key': apiKey
    }
    return requests.get(url=url, headers=headers, params=querystring)


def get_results_ipdb(ipList, apiKey, outputFile, days):
    i = 0
    headers = []
    output = []
    for ip in ipList:
        i += 1
        print("Getting AbuseIPDB response for ip #" +
              str(i) + " of " + str(len(ipList)))
        response = request_ipdb(apiKey, ip, days)
        #
        if response.status_code == 200:
            # Loads response into JSON
            decodedResponse = json.loads(response.text)
            puredata = decodedResponse["data"]
            puredata['Link'] = "https://www.abuseipdb.com/check/"+ip
            datos = []
            # Get headers and data
            for key, value in puredata.items():
                if i == 1:
                    headers.append(key)
                    output = [headers, ]
                if value == None:
                    value = 'None'
                datos.append(value)
        elif response.status_code == 429:
            print("API Key reached it's limit. HTTP 429 response code")
        else:
            print("There was a problem in the request. HTTP response code: " +
                  str(response.status_code))
        output.append(datos)
    write_output(outputFile, output, 'w')


if __name__ == "__main__":
    args = vars(create_arguments())
    apiKey = args['key']
    outputFile = args['output']
    ipList = args['ips']
    days = args['days']
    if ipList == None:
        ipList = get_ips()
    # Get Results
    get_results_ipdb(ipList, apiKey, outputFile, days)
    pass