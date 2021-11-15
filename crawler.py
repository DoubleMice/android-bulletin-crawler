# coding: utf-8
import os
import requests
import csv

from proxy_setting import *
from urllib.parse import urljoin
from pyquery import PyQuery as pq

HOST_URL = "https://source.android.com"
BULLETIN_URL = 'https://source.android.com/security/bulletin'

class csvWriter:
    def __init__(self, csvName, outDir="AndroidBulletin"):
        self.fieldnames = ["Component", "CVE", "References", "Type", "Severity", "Updated AOSP versions"]
        if not csvName.endswith(".csv"):
            csvName += ".csv"
        if outDir != "" and not os.path.exists(outDir):
            os.mkdir(outDir)
        self.csvFile = open(os.path.join(outDir, csvName), "w", newline="")
        self.writer = csv.DictWriter(self.csvFile, fieldnames=self.fieldnames)
        self.writer.writeheader()

    def write(self, component, cve, ref, vultype, severity, version):
        if cve == "":
            return
        self.writer.writerow({
            "Component" : component,
            "CVE" : cve,
            "References" : ref,
            "Type" : vultype,
            "Severity" : severity,
            "Updated AOSP versions" : version
        })
        self.csvFile.flush()

    def close(self):
        self.csvFile.close()


def getBulletinPath(resp):
    urlList = []
    cnt = 1
    while True:
        url = pq(resp.text)('table').children('tr').eq(cnt)("a").attr["href"]
        if url == None:
            return urlList
        cnt += 1
        urlList.append(url)

def save2Csv(cveResp, csvName):
    # CVEInfos = []
    csvObj = csvWriter(csvName)
    for i in range(len(pq(cveResp.text)("div.devsite-article-body")("h3"))):
        table = pq(cveResp.text)("div.devsite-article-body")("table").eq(i)
        if table == None:
            continue
        component = pq(cveResp.text)("div.devsite-article-body")("h3").eq(i).text()
        # CVEInfo = table("td")
        for j in range(len(table("tr"))):
            tr = table("tr").eq(j)
            cve = tr("td").eq(0).text().replace("\n", ", ")
            ref = tr("td").eq(1).text().replace("\n", ", ")
            vultype = tr("td").eq(2).text().replace("\n", ", ")
            severity = tr("td").eq(3).text().replace("\n", ", ")
            version = tr("td").eq(4).text().replace("\n", ", ")
            csvObj.write(component, cve, ref, vultype, severity, version)
    csvObj.close()

def parseBulletinUrl(pathList):
    for path in pathList:
        print("[+] parsing", path)
        cveResp = requests.get(urljoin(BULLETIN_URL, path), verify=False, proxies=get_default_proxy())
        save2Csv(cveResp, path.split("/")[-1])

if __name__ == "__main__":
    resp = requests.get(BULLETIN_URL, verify=False, proxies=get_default_proxy())
    parseBulletinUrl(getBulletinPath(resp))
