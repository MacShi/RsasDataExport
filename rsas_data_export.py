
from lxml import etree
import pandas as pd

def score2risk(score:float)->str:
    '''
    :param score: 分数
    :return: 返回漏洞等级
     高 	7 <= 漏洞风险值 <= 10 
     中 	4 <= 漏洞风险值 < 7 
     低 	0 <= 漏洞风险值 < 4
    '''

    if 7<=score<=10:
        return "高"
    elif 4<= score<7:
        return "中"
    else:
        return "低"
def parseXml(path:str):
    '''

    :param path: xml文件路径
    :return: 无返回
    '''
    parser = etree.XMLParser(encoding="utf-8")
    xml = etree.parse(path,parser=parser)
    targets = xml.xpath("//targets/target")
    for target in targets:
        host = target.xpath("ip/text()")[0] if len(target.xpath("ip/text()")) ==1 else "无IP地址"
        print(host)
        vulnXml = target.xpath("vuln_detail/vuln")
        vulInfos = []
        for vuln in vulnXml:
            vulInfo = []
            name = vuln.xpath("name/text()")[0] if len(vuln.xpath("name/text()")) ==1 else "无"
            threat_category = vuln.xpath("threat_category/text()")[0] if len(vuln.xpath("threat_category/text()")) ==1 else "无"
            cve_id = vuln.xpath("cve_id/text()")[0] if len(vuln.xpath("cve_id/text()")) ==1 else "无"
            risk = score2risk(float(vuln.xpath("risk_points/text()")[0])) if len(vuln.xpath("risk_points/text()")) ==1 else "无"
            # print(vuln.xpath("risk_points/text()")[0])
            solution = vuln.xpath("solution/text()")[0] if len(vuln.xpath("solution/text()")[0]) >0  else "无"
            description =  vuln.xpath("description/text()")[0] if len(vuln.xpath("description/text()"))==1 else "无"
            vulInfo.append(name)
            vulInfo.append(threat_category)
            vulInfo.append(cve_id)
            vulInfo.append(risk)
            vulInfo.append(solution)
            vulInfo.append(description)
            # print("名字：{},威胁信息：{},CVE-ID：{},威胁等级：{},解决方法：{},描述:{}".format(name,threat_category,cve_id,risk,solution,description))
            vulInfos.append(vulInfo)
    print(vulInfos)
    df = pd.DataFrame(vulInfos, columns=['漏洞名称',"威胁类型","CVE","风险等级","解决方法", '漏洞描述'])
    df.to_excel("{}.xlsx".format(host), index=False)


if __name__ == '__main__':
    parseXml(r'..\data\xml\1248.xml')