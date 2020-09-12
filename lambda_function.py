import boto3
import math
import time
import json
import datetime
import logging
import os
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
logger = logging.getLogger()
logger.setLevel(logging.INFO)
API_CALL_NUM_RETRIES = 1
ACLMETATABLE = os.environ['ACLMETATABLE']
SNSTOPIC = os.environ['SNSTOPIC']
def get_netacl_id(subnet_id):
    try:
        ec2 = boto3.client('ec2')
        response = ec2.describe_network_acls(
            Filters=[
                {
                    'Name': 'association.subnet-id',
                    'Values': [
                        subnet_id,
                    ]
                }
            ]
        )
        netacls = response['NetworkAcls'][0]['Associations']
        for i in netacls:
            if i['SubnetId'] == subnet_id:
                netaclid = i['NetworkAclId']
        return netaclid
    except Exception as e:
        return []
def get_nacl_rules(netacl_id):
    ec2 = boto3.client('ec2')
    response = ec2.describe_network_acls(
        NetworkAclIds=[
            netacl_id,
            ]
    )
    naclrules = []
    for i in response['NetworkAcls'][0]['Entries']:
        naclrules.append(i['RuleNumber'])
    naclrulesf = list(filter(lambda x: 71 <= x <= 80, naclrules))
    return naclrulesf
def get_nacl_meta(netacl_id):
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)
    ec2 = boto3.client('ec2')
    response = ec2.describe_network_acls(
        NetworkAclIds=[
            netacl_id,
            ]
    )
    ddbresponse = table.scan()
    ddbentries = response['Items']
    netacl = ddbresponse['NetworkAcls'][0]['Entries']
    naclentries = []
    for i in netacl:
            entries.append(i)
    return naclentries
def update_nacl(netacl_id, host_ip, region):
    logger.info("log -- GD2ACL entering update_nacl, netacl_id=%s, host_ip=%s" % (netacl_id, host_ip))
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)
    timestamp = int(time.time())
    hostipexists = table.query(
        KeyConditionExpression=Key('NetACLId').eq(netacl_id),
        FilterExpression=Attr('HostIp').eq(host_ip)
    )
    if len(hostipexists['Items']) > 0:
        logger.info("log -- host IP %s already in table... exiting GD2ACL update." % (host_ip))
    else:
        response = table.query(
            KeyConditionExpression=Key('NetACLId').eq(netacl_id)
        )
        naclentries = response['Items']
        if naclentries:
            rulecount = response['Count']
            rulerange = list(range(71, 81))
            ddbrulerange = []
            naclrulerange = get_nacl_rules(netacl_id)
            for i in naclentries:
                ddbrulerange.append(int(i['RuleNo']))
            ddbrulerange.sort()
            naclrulerange.sort()
            synccheck = set(naclrulerange).symmetric_difference(ddbrulerange)
            if ddbrulerange != naclrulerange:
                logger.info("log -- current DDB entries, %s." % (ddbrulerange))
                logger.info("log -- current NACL entries, %s." % (naclrulerange))
                logger.error('NACL rule state mismatch, %s exiting' % (sorted(synccheck)))
                exit()
            if rulecount < 10:
                newruleno = min([x for x in rulerange if not x in naclrulerange])
                logger.info("log -- adding new rule %s, HostIP %s, to NACL %s." % (newruleno, host_ip, netacl_id))
                create_netacl_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno)
                create_ddb_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno, region=region)
                logger.info("log -- all possible NACL rule numbers, %s." % (rulerange))
                logger.info("log -- current DDB entries, %s." % (ddbrulerange))
                logger.info("log -- current NACL entries, %s." % (naclrulerange))
                logger.info("log -- new rule number, %s." % (newruleno))
                logger.info("log -- rule count for NACL %s is %s." % (netacl_id, int(rulecount) + 1))
            if rulecount >= 10:
                oldestrule = table.query(
                    KeyConditionExpression=Key('NetACLId').eq(netacl_id),
                    ScanIndexForward=True, 
                    Limit=1,
                )
                oldruleno = int((oldestrule)['Items'][0]['RuleNo'])
                oldrulets = int((oldestrule)['Items'][0]['CreatedAt'])
                oldhostip = oldestrule['Items'][0]['HostIp']
                newruleno = oldruleno
                logger.info("log -- deleting current rule %s for IP %s from NACL %s." % (oldruleno, oldhostip, netacl_id))
                delete_netacl_rule(netacl_id=netacl_id, rule_no=oldruleno)
                delete_ddb_rule(netacl_id=netacl_id, created_at=oldrulets)
                response_nonexpired = table.scan( FilterExpression=Attr('CreatedAt').gt(oldrulets) & Attr('HostIp').eq(host_ip) )
                logger.info("log -- adding new rule %s, HostIP %s, to NACL %s." % (newruleno, host_ip, netacl_id))
                create_netacl_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno)
                create_ddb_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno, region=region)
                logger.info("log -- all possible NACL rule numbers, %s." % (rulerange))
                logger.info("log -- current DDB entries, %s." % (ddbrulerange))
                logger.info("log -- current NACL entries, %s." % (naclrulerange))
                logger.info("log -- rule count for NACL %s is %s." % (netacl_id, int(rulecount)))
        else:
            naclrulerange = get_nacl_rules(netacl_id)
            newruleno = 71
            oldruleno = []
            rulecount = 0
            naclrulerange.sort()
            if naclrulerange:
                logger.error("log -- NACL has existing entries, %s." % (naclrulerange))
                exit()
            logger.info("log -- adding new rule %s, HostIP %s, to NACL %s." % (newruleno, host_ip, netacl_id))
            create_netacl_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno)
            create_ddb_rule(netacl_id=netacl_id, host_ip=host_ip, rule_no=newruleno, region=region)
            logger.info("log -- rule count for NACL %s is %s." % (netacl_id, int(rulecount) + 1))
        if response['ResponseMetadata']['HTTPStatusCode'] == 200:
            return True
        else:
            return False
def create_netacl_rule(netacl_id, host_ip, rule_no):
    ec2 = boto3.resource('ec2')
    network_acl = ec2.NetworkAcl(netacl_id)
    response = network_acl.create_entry(
    CidrBlock = host_ip + '/32',
    Egress=False,
    PortRange={
        'From': 0,
        'To': 65535
    },
    Protocol='-1',
    RuleAction='deny',
    RuleNumber= rule_no
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info("log -- successfully added new rule %s, HostIP %s, to NACL %s." % (rule_no, host_ip, netacl_id))
        return True
    else:
        logger.error("log -- error adding new rule %s, HostIP %s, to NACL %s." % (rule_no, host_ip, netacl_id))
        logger.info(response)
        return False
def delete_netacl_rule(netacl_id, rule_no):
    ec2 = boto3.resource('ec2')
    network_acl = ec2.NetworkAcl(netacl_id)
    response = network_acl.delete_entry(
        Egress=False,
        RuleNumber=rule_no
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info("log -- successfully deleted rule %s, from NACL %s." % (rule_no, netacl_id))
        return True
    else:
        logger.info("log -- error deleting rule %s, from NACL %s." % (rule_no, netacl_id))
        logger.info(response)
        return False
def create_ddb_rule(netacl_id, host_ip, rule_no, region):
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)
    timestamp = int(time.time())
    response = table.put_item(
        Item={
            'NetACLId': netacl_id,
            'CreatedAt': timestamp,
            'HostIp': str(host_ip),
            'RuleNo': str(rule_no),
            'Region': str(region)
            }
        )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info("log -- successfully added DDB state entry for rule %s, HostIP %s, NACL %s." % (rule_no, host_ip, netacl_id))
        return True
    else:
        logger.error("log -- error adding DDB state entry for rule %s, HostIP %s, NACL %s." % (rule_no, host_ip, netacl_id))
        logger.info(response)
        return False
def delete_ddb_rule(netacl_id, created_at):
    ddb = boto3.resource('dynamodb')
    table = ddb.Table(ACLMETATABLE)
    timestamp = int(time.time())
    response = table.delete_item(
        Key={
            'NetACLId': netacl_id,
            'CreatedAt': int(created_at)
            }
        )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        logger.info("log -- successfully deleted DDB state entry for NACL %s." % (netacl_id))
        return True
    else:
        logger.error("log -- error deleting DDB state entry for NACL %s." % (netacl_id))
        logger.info(response)
        return False
def admin_notify(iphost, findingtype, naclid, region, instanceid):
    MESSAGE = ("GuardDuty to ACL Event Info:\r\n"
                 "Suspicious activity detected from host " + iphost + " due to " + findingtype + "."
                 "  The following ACL resources were targeted for update as needed; "
                 "VPC NACL: " + naclid + ", "
                 "EC2 Instance: " + instanceid + ", "
                 "Region: " + region + ". "
                )
    sns = boto3.client(service_name="sns")
    try:
        sns.publish(
            TopicArn = SNSTOPIC,
            Message = MESSAGE,
            Subject='AWS GD2ACL Alert'
        )
        logger.info("log -- send notification sent to SNS Topic: %s" % (SNSTOPIC))
    except ClientError as e:
        logger.error('log -- error sending notification.')
        raise
def lambda_handler(event, context):
    logger.info("log -- Event: %s " % json.dumps(event))
    try:
        if event["detail"]["type"] == 'Recon:EC2/PortProbeUnprotectedPort':
                HostIp = []
                Region = event["region"]
                SubnetId = event["detail"]["resource"]["instanceDetails"]["networkInterfaces"][0]["subnetId"]
                for i in event["detail"]["service"]["action"]["portProbeAction"]["portProbeDetails"]:
                    HostIp.append(str(i["remoteIpDetails"]["ipAddressV4"]))
                instanceID = event["detail"]["resource"]["instanceDetails"]["instanceId"]
                NetworkAclId = get_netacl_id(subnet_id=SubnetId)
        else:
            Region = event["region"]
            SubnetId = event["detail"]["resource"]["instanceDetails"]["networkInterfaces"][0]["subnetId"]
            HostIp = [event["detail"]["service"]["action"]["networkConnectionAction"]["remoteIpDetails"]["ipAddressV4"]]
            instanceID = event["detail"]["resource"]["instanceDetails"]["instanceId"]
            NetworkAclId = get_netacl_id(subnet_id=SubnetId)
        if NetworkAclId:
            for ip in HostIp:
                response = update_nacl(netacl_id=NetworkAclId, host_ip=ip, region=Region)
            admin_notify(str(HostIp), event["detail"]["type"], NetworkAclId, Region, instanceid = instanceID)
            logger.info("log -- processing GuardDuty finding completed successfully")
        else:
            logger.info("log -- unable to determine NetworkAclId for instanceID: %s, HostIp: %s, SubnetId: %s. Confirm resources exist." % (instanceID, HostIp, SubnetId))
            pass
    except Exception as e:
        logger.error('log -- something went wrong.')
        raise