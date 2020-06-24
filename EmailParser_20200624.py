#!/usr/bin/python3
# -*- coding: utf-8 -*-
# **********************************************************************;
# Project           : bCIRT
# License           : GPL-3.0
# Program name      : scripts/mailparser_bcirt_v8.py
# Author            : Balazs Lendvay
# Date created      : 2019.01.24
# Purpose           : Email parser script for the bCIRT
# Revision History  : v9
# Date        Author      Ref    Description
# 2019.01.24  Lendvay     1      Initial file
# 2020.05.25  Lendvay     2      Added IP parser
# 2020.06.09  Lendvay     2      JSON parser issue with binary data
# 2020.06.24  Lendvay     2      parameter save_attachments fix
# **********************************************************************;
# URL: https://github.com/SpamScope/mail-parser
# The current version of mail-parser has a bug, it prints an error message. It has to be located in the package and
# manually bypassed FYI
import mailparser
import os
import base64
import json
import re
import urllib
import argparse


class mail_analyser():
    def __init__(self, mypath, nfile):
        self.mypath = mypath
        self.nfile = nfile
        self.onemail = None
        self.retval = None

        filepath = os.path.join(mypath, nfile)
        if not os.path.isfile(filepath):
            print("File not found!")
            exit(1)

        matchObj = re.match(r'.*.(msg|eml)$', nfile, re.M | re.I)
        if matchObj:
            if matchObj.group(1) == "msg":
                self.onemail = mailparser.parse_from_file_msg(filepath)
            elif matchObj.group(1) == "eml":
                self.onemail = mailparser.parse_from_file(filepath)
            else:
                print("Unsupported file type!")
                exit(1)
        else:
            print("Unsupported file type!")
            exit(1)

        if not self.onemail.headers:
            print("Broken file!")
            exit(1)
        self.retval = self.analyse_email()

    def analyse_email(self):
        header_date = (self.onemail.date.strftime('%Y-%m-%d %H:%M:%S'),)

        header_from = []
        realfrom = ''
        goodfrom = ()
        for v1 in self.onemail.from_:
            if '@' not in v1[1]:
                realfrom += v1[1]
            else:
                goodfrom += v1
        if realfrom != '' and goodfrom == ():
            header_from += [(realfrom,)]
        elif goodfrom != () and realfrom == '':
            header_from = [goodfrom]
        elif goodfrom != () and realfrom != '':
            header_from = [goodfrom, (realfrom,)]
        else:
            header_from = []

        header_from_dict = header_from[0]

        header_to = self.onemail.to
        header_to_dict = header_to

        header_cc = self.onemail.cc
        header_cc_dict = header_cc
        header_bcc = self.onemail.bcc
        header_bcc_dict = header_bcc
        header_replyto = self.onemail.Reply_To

        if self.onemail.Return_Path:
            header_returnpath = [('', self.onemail.Return_Path)]
        else:
            header_returnpath = []

        header_messageid = (self.onemail.Message_ID,)
        header_messageid_domain = (header_messageid[0].split('@')[1][0:-1],)
        header_subject = self.onemail.subject.encode('utf8')
        header_attachments = self.list_attachments()

        clean_authresults = ""
        AR_SPF = ()
        AR_SPF_check = ()
        AR_DKIM = ()
        AR_headerd = ()
        AR_DMARC = ()
        AR_action = ()
        AR_headerfrom = ()
        if self.onemail.Authentication_Results:
            header_authenticationresults = (self.onemail.Authentication_Results,)
            clean_authresults = header_authenticationresults[0].replace('\n', '')
            matchObj = re.search(r'.*spf=(\S+) \(', clean_authresults, re.M | re.I)
            if matchObj:
                AR_SPF = matchObj.group(1)
            matchObj = re.search(r' \((.*) dkim=', clean_authresults, re.M | re.I)
            if matchObj:
                AR_SPF_check = matchObj.group(1)
            matchObj = re.search(r' dkim=(.*) header.d=', clean_authresults, re.M | re.I)
            if matchObj:
                AR_DKIM = matchObj.group(1)
            matchObj = re.search(r' header.d=(\S+) dmarc=', clean_authresults, re.M | re.I)
            if matchObj:
                AR_headerd = matchObj.group(1)
            matchObj = re.search(r' dmarc=(\S+) action=', clean_authresults, re.M | re.I)
            if matchObj:
                AR_DMARC = matchObj.group(1)
            matchObj = re.search(r' action=(\S+) header.from', clean_authresults, re.M | re.I)
            if matchObj:
                AR_action = matchObj.group(1)
            matchObj = re.search(r' header.from=(\S+)(;| )', clean_authresults, re.M | re.I)
            if matchObj:
                AR_headerfrom = matchObj.group(1)
        else:
            header_authenticationresults = []

        clean_receivedspf = []
        RCV_SPF = ""
        RCV_spf_check = ""
        RCV_SPF_receiver = ""
        RCV_SPF_clientip = ""
        RCV_SPF_helo = ""
        if self.onemail.received_spf:
            alist = list()
            receivedspf = self.onemail.received_spf
            if type(receivedspf) == type(alist):
                header_receivedspf = (receivedspf[0],)
            else:
                header_receivedspf = (receivedspf,)
            # header_receivedspf = (self.onemail.received_spf,)
            clean_receivedspf = header_receivedspf[0].replace('\n', '').replace('\n', '')
            matchObj = re.search(r'(\S+) ', clean_receivedspf, re.M | re.I)
            if matchObj:
                RCV_SPF = matchObj.group(1)
            matchObj = re.search(r' \((.*)\)', clean_receivedspf, re.M | re.I)
            if matchObj:
                RCV_spf_check = matchObj.group(1)
            matchObj = re.search(r' receiver=(\S+);', clean_receivedspf, re.M | re.I)
            if matchObj:
                RCV_SPF_receiver = matchObj.group(1)
            matchObj = re.search(r' client-ip=([0-9.]+).* ', clean_receivedspf, re.M | re.I)
            if matchObj:
                RCV_SPF_clientip = matchObj.group(1)
            matchObj = re.search(r' helo=(.*);', clean_receivedspf, re.M | re.I)
            if matchObj:
                RCV_SPF_helo = matchObj.group(1)
        else:
            header_receivedspf = []

        if self.onemail.received:
            header_received = self.onemail.received[0]
        else:
            header_received = []

        allurls = self.list_urls(True)

        alldefects = self.onemail.defects

        allemaillist = header_from + header_to + header_cc + header_bcc + header_replyto + header_returnpath
        allemails = set()
        for anemail in allemaillist:
            if len(anemail) > 1:
                if '@' in anemail[1]:
                    allemails.add(anemail[1])

        allemails = tuple(allemails)

        retvalfull = {
            'Filename': nfile,
            'Date': header_date[0],
            'MessageID': header_messageid[0],
            'MessageID-Domain': header_messageid_domain[0],
            'From': header_from_dict,
            'To': header_to_dict,
            'CC': header_cc_dict,
            'BCC': header_bcc_dict,
            'Return-Path': list(header_returnpath),
            'Reply-To': list(header_replyto),
            'Subject': header_subject,
            'Attachments': list(header_attachments),
            # 'AuthRes':str(header_authenticationresults),
            'AuthRes_SPF': AR_SPF,
            'AuthRes_SPF-check': AR_SPF_check,
            'AuthRes_DKIM': AR_DKIM,
            'AuthRes_headerd': AR_headerd,
            'AuthRes_DMARC': AR_DMARC,
            'AuthRes_action': AR_action,
            'AuthRes_headerfrom': AR_headerfrom,
            # 'Received-SPF-raw': str(header_receivedspf),
            'Received-SPF': RCV_SPF,
            'Received-SPF-check': RCV_spf_check,
            'Received-SPF-receiver': RCV_SPF_receiver,
            'Received-SPF-clientip': RCV_SPF_clientip,
            'Received-SPF-helo': RCV_SPF_helo,
            'Received': header_received,
            # 'Body': str(body_content),
            'AllURLs': list(allurls),
            # 'AllEmails': list(allemails),
            'AllEmails': list(allemails),
            'AllDefects': list(alldefects),

        }
        return retvalfull

    def save_attachments(self, pmypath):
        header_attachments = []
        if self.onemail.attachments:
            for values in self.onemail.attachments:
                header_attachments += [(values['filename'], values['mail_content_type'],)]

                # newfilename = pnfile + "_" + values['filename']
                newfilename = values['filename']
                newfilepath = os.path.join(pmypath, newfilename)
                f = open(newfilepath, 'w+b')
                # byte_arr = [120, 3, 255, 0, 100]
                binary_format = bytearray(base64.b64decode(values['payload']))
                # print(values['payload'])
                f.write(binary_format)
                f.close()
        return header_attachments

    def list_attachments(self):
        header_attachments = []
        if self.onemail.attachments:
            for values in self.onemail.attachments:
                header_attachments += [(values['filename'], values['mail_content_type'],)]
        return header_attachments

    def save_screenshot(self, pmypath, pnfile):
        body_content = [((self.onemail.text_plain), (self.onemail.text_html))]
        if body_content[0][0]:
            body_plain = body_content[0][0][0]
            # print(body_plain)
            if body_plain:
                newfilename = pnfile + "." + 'txt'
                newfilepath = os.path.join(pmypath, newfilename)
                f = open(newfilepath, 'w+t')
                # byte_arr = [120, 3, 255, 0, 100]
                # binary_format = bytearray(base64.b64decode(body_content))
                # print(values['payload'])
                f.write(str(body_plain))
                f.close()

        if body_content[0][1]:
            body_html = body_content[0][1][0]
            if body_html:
                newfilename = pnfile + "." + 'html'
                newfilepath = os.path.join(pmypath, newfilename)
                f = open(newfilepath, 'w+t')
                # byte_arr = [120, 3, 255, 0, 100]
                # binary_format = bytearray(base64.b64decode(body_content))
                # print(values['payload'])
                f.write(body_html)
                f.close()
        return 1

    def list_urls(self, safelink):
        urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                          self.onemail.body)
        allurls = set()
        for url in urls:
            url_clean = urllib.parse.unquote(url)
            if safelink:
                allurls.add(self.safelink_extract(url_clean))
            else:
                allurls.add(url_clean)
        allurls = tuple(allurls)
        return allurls

    def list_ipv4s(self):
        ipattern = re.compile(
            '(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)')
        imatches = re.findall(ipattern, self.onemail.body)
        imatches = sorted(list(set(imatches)))

        imatches2 = re.findall(ipattern, str(self.onemail.headers))
        imatches2 = sorted(list(set(imatches2)))
        allips = set()
        for imatch in imatches:
            allips.add(imatch+" ")
        for imatch2 in imatches2:
            allips.add(imatch2+" ")
        allips = tuple(allips)
        return allips

    def safelink_extract(self, ptext):
        # https:\/\/.*.safelinks.protection.outlook.com\/\?url=(.*)(&data=|&amp;data=).*
        urls = re.search('https:\/\/.*.safelinks.protection.outlook.com\/\?url=(.*)(&data=|&amp;data=).*', ptext)
        if urls:
            returl = urls.group(1)
        else:
            returl = ptext
        return returl

    def print_result(self):
        for key in self.retval:
            outstr = str(key).encode('utf8') + str(":").encode('utf8') + str(self.retval[key]).encode('utf8')
            print(repr(outstr)[2:-1])
        # print(self.retval)

    def print_result_json(self):
        # for key in self.retval:
        #     print(key + ":" + self.retval[key])
        try:
            retval = json.dumps(self.retval, sort_keys=False, indent=4)
        except:
            retval = json.dumps(str(self.retval), sort_keys=False, indent=4)
        print(retval)

    def list_emails(self):
        print(str(self.retval['AllEmails'])[1:-1])


def build_parser():
    parser = argparse.ArgumentParser(description='Process email file.', usage='email_parser [options]')
    parser.add_argument("PATH", help="Directory path to the file")
    parser.add_argument('-p', '--print', action='store_true', help='Print the analysis results')
    # self.parser.add_argument('-a', '--attachment', type=str, help='Save attachments', dest="<file-path>")
    parser.add_argument('-a', '--attachment', action='store', type=str, help='Save attachments',
                        dest="save-attachment-to")
    parser.add_argument('-b', '--savebody', action='store', type=str, help='Save body contents to file',
                        dest="save-body-to")
    parser.add_argument('-u', '--urls', action='store', type=int,
                        help='Print urls in body if 1, extract safelinks if 2', dest="urls")
    parser.add_argument('--ipv4', action='store_true', help='Print IPv4 addresses in body and header', dest="ipv4")
    parser.add_argument('-e', '--emails', action='store_true', help='Print emails in body')
    parser.add_argument('-j', '--json', action='store_true', help='Print results in JSON format')

    retargs = vars(parser.parse_args())
    # retargs = self.parser.parse_args()
    return retargs


if __name__ == "__main__":
    args = build_parser()
    # print(args)

    npath = os.path.dirname(args['PATH'])
    nfile = os.path.basename(args['PATH'])

    if args['print']:
        inst1 = str(mail_analyser(npath, nfile).print_result())
    if args['json']:
        inst1 = mail_analyser(npath, nfile).print_result_json()
    if args['save-attachment-to']:
        napath = os.path.dirname(args['save-attachment-to'])
        # nafile = os.path.basename(args['save-attachment-to'])
        inst2 = mail_analyser(npath, nfile).save_attachments(napath)
    if args['save-body-to']:
        nspath = os.path.dirname(args['save-body-to'])
        # nsfile = os.path.basename(args['save-body-to'])
        inst3 = mail_analyser(npath, nfile).save_screenshot(nspath, nfile)
    if args['urls'] == 1:
        inst4 = mail_analyser(npath, nfile).list_urls(False)
        #print(",".join(inst4))
        print(inst4)
    elif args['urls'] == 2:
        inst4 = mail_analyser(npath, nfile).list_urls(True)
        #print(",".join(inst4))
        print(inst4)
    if args['ipv4']:
        inst5 = mail_analyser(npath, nfile).list_ipv4s()
        print(inst5)
    if args['emails']:
        inst6 = mail_analyser(npath, nfile).list_emails()
    if args['json']:
        inst7 = mail_analyser(npath, nfile).print_result_json()
