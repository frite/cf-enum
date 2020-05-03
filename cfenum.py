#!/usr/bin/env python3
''' Cloudflare enumeration script that leverages Cloudflare tokens.
Requires the email you used to register in Cloudflare and your Global
API key.'''
import logging
import argparse
import os
import sys
import json
import time
import CloudFlare

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
    )


def parsing():
    ''' Parser options
    -d/--domain holds the domain to scan
    -o/--output the file/path to store the file
    '''
    parser = argparse.ArgumentParser(
                formatter_class=argparse.ArgumentDefaultsHelpFormatter
                )

    parser.add_argument('-d', '--domain',
                        help='The domain to scan.',
                        required=True
                        )

    parser.add_argument('-o', '--output',
                        help='The file to store the subdomains found.',
                        dest='output_file',
                        required=True
                        )

    parser.add_argument('--cf-email',
                        help='The email used to register the CF account.',
                        dest='cf_email'
                        )

    parser.add_argument('--cf-token',
                        help='The Global API token.',
                        dest='cf_token'
                        )

    return parser


def get_tokens(args):
    ''' Ensure that the user has set the proper tokens. If not, bail
    out. Tokens should be set either as env variables or passed in
    through CLI arguments. If they are not set, log and exit.
    '''

    if args.cf_email and args.cf_token:
        cf_email = args.cf_email
        cf_token = args.cf_token
    elif 'CF_EMAIL' in os.environ and 'CF_TOKEN' in os.environ:
        cf_email = os.environ['CF_EMAIL']
        cf_token = os.environ['CF_TOKEN']
    else:
        logging.warning('[!] Cloudfare email and Global API token should be set'
                        ' either as environment vars (CF_EMAIL'
                        ', CF_TOKEN) or through the cli'
                        'options (--cf-email,'
                        '--cf-token),'
                        'exiting.')
        sys.exit(1)

    return(cf_email, cf_token)


class CFEnum:
    ''' Class to handle all the interactions with Cloudflare API.'''

    cloudflare_api = None
    zones = None

    def __init__(self, email, token):
        ''' Main class constructor.
        :param email [Cloudflare registration email]
        :param token [Cloudflare Global API token]
        '''
        self.cloudflare_api = CloudFlare.CloudFlare(email=email, token=token)
        self.zones = self.__get_zones()


    def __get_zones(self):
        ''' Get all the zones of a user.'''
        zones = []
        page_number = 0
        while True:
            page_number += 1
            try:
                results = self.cloudflare_api.zones(
                    params={'per_page': 20,
                            'page': page_number})
            except CloudFlare.exceptions.CloudFlareAPIError:
                logging.warning('[!] Something went wrong while getting'
                                'zones. Exiting.')
                sys.exit(1)

            #  For unknown reasons, CloudFlare API doesn't return page count.
            if not results:
                break

            for result in results:
                zones.append({'domain': result['name'], 'id': result['id'],
                              'nameservers':[result['original_name_servers'],
                                             result['name_servers']]})

        return zones

    def __site_exists(self, domain):
        ''' Ensure that the domain requested is not in some account
        already.'''
        for zone in self.zones:
            if domain in zone['domain']:
                logging.info('[!] Domain %s already in account.', domain)
                return zone['id']
        return None

    def __parse_results(self, domain, subdomains):
        ''' Parse results and return them '''
        return {'domain': domain, 'subdomains' : subdomains}


    def __create_zone(self, domain):
        try:
            zone_info = self.cloudflare_api.zones.post(data={
                'jump_start': True,
                'name': domain
                })
            return zone_info['id']
        except CloudFlare.exceptions.CloudFlareAPIError as exception:
            if "banned" in str(exception):
                logging.warning('[!] Domain %s can\'t be added to CloudFlare.'
                                ' Exiting.', domain)
            else:
                logging.warning('[!] API Error while creating zone for %s'
                                '. Exiting', domain)
            sys.exit(1)
        except Exception:
            logging.warning('[!] Error while creating zone for %s.'
                            'Exiting', domain)
            sys.exit(1)
        return None


    def __get_subdomains(self, zone_id):
        subdomains = []
        page_number = 0
        while True:
            page_number += 1
            try:
                results = self.cloudflare_api.zones.dns_records.get(
                    zone_id,
                    params={'per_page': 50,
                            'page': page_number})
            except CloudFlare.exceptions.CloudFlareError:
                logging.warning('[!] Something went wrong while getting'
                                'zones. Exiting.')
                sys.exit(1)

            #  For unknown reasons, CloudFlare API doesn't return page count.
            if not results:
                break

            for result in results:
                subdomains.append({'subdomain': result['name'],
                                   'type': result['type'],
                                   'IP': result['content']})
        return subdomains


    def __delete_zone(self, zone_id):
        logging.info('[*] Cleaning up zone')
        try:
            self.cloudflare_api.zones.delete(zone_id)
        except CloudFlare.exceptions.CloudFlareError:
            logging.warning('[!] Something went wrong while deleting'
                            'zone %s. Exiting.', zone_id)
            sys.exit(1)


    def get_subdomains(self, domain):
        ''' If user already has the given domain, return the results.
            If user doesn't have it, create zone, fetch results and
            remove zone.
        '''
        zone_id = self.__site_exists(domain)
        if zone_id:
            subdomains = self.__get_subdomains(zone_id)
        else:
            logging.info('[*] %s not in account. Creating it',
                         domain)
            zone_id = self.__create_zone(domain)
            time.sleep(30)
            subdomains = self.__get_subdomains(zone_id)
            logging.info('[*] Cleaning up zone created for %s', domain)
            self.__delete_zone(zone_id)

        return self.__parse_results(domain, subdomains)

def write_to_json(filename, data):
    ''' Write results to JSON file. '''
    try:
        with open(filename, 'w') as outfile:
            json.dump(data, outfile)
            file_path = os.path.abspath(outfile.name)
            logging.info('[+] Results written to JSON file : %s',
                         file_path)
    except IOError:
        logging.warning('[+] Failed to write results to JSON file : %s',
                        file_path)
        sys.exit(1)


def main():
    ''' Main functionality here to avoid globbing. '''
    parser = parsing()
    args = parser.parse_args()
    tokens = get_tokens(args)
    cloudfare_enum = CFEnum(tokens[0], tokens[1])
    write_to_json(args.output_file, cloudfare_enum.get_subdomains(args.domain))


if __name__ == '__main__':
    main()
