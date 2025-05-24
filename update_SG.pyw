# this script checks the IPs of hostnames with dynamic IPs and 
# update the security group on AWS (inbound and outbound)
# limitation: script doesn't work properly if you have a 0.0.0.0 rule on the SG

import boto3
import socket

HOSTNAMES = [''] # insert hostnames here, assumming there are multiple
SECURITY_GROUP_ID = '' # insert the AWS security group ID
PORT = '' # insert port number here
PROTOCOL = 'tcp' 
REGION = '' # insert aws Region here

def resolve_ips(hostnames):
    ip_set = set()
    for hostname in hostnames:
        results = socket.getaddrinfo(hostname, None)
        for res in results:
            ip_set.add(res[4][0])
    return ip_set

def get_sg_ips(sg_id, port, protocol, ec2, dir):
    sg = ec2.SecurityGroup(sg_id)
    current_ips = set()
    if dir == 'ingress':  
        for perm in sg.ip_permissions:
            if perm.get('FromPort') == port and perm.get('IpProtocol') == protocol:
                for ip_range in perm.get('IpRanges', []):
                    current_ips.add(ip_range['CidrIp'].replace('/32', ''))
    elif dir == 'egress':
        for perm in sg.ip_permissions_egress:
            if perm.get('FromPort') == port and perm.get('IpProtocol') == protocol:
                for ip_range in perm.get('IpRanges', []):
                    current_ips.add(ip_range['CidrIp'].replace('/32', ''))
    return current_ips

def update_sg(sg_id, old_ips, new_ips, port, protocol, ec2, dir):
    sg = ec2.SecurityGroup(sg_id)
    to_revoke = old_ips - new_ips
    to_authorize = new_ips - old_ips

    if to_revoke:
        if dir == 'ingress':
            sg.revoke_ingress(
                IpPermissions=[{
                    'IpProtocol': protocol,
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': [{'CidrIp': f'{ip}/32'} for ip in to_revoke]
                }]
            )
        elif dir == 'egress':
            sg.revoke_egress(
               IpPermissions=[{
                   'IpProtocol': protocol,
                   'FromPort': port,
                   'ToPort': port,
                   'IpRanges': [{'CidrIp': f'{ip}/32'} for ip in to_revoke]
               }]
            )

    if to_authorize:
        if dir == 'ingress':
            sg.authorize_ingress(
                IpPermissions=[{
                    'IpProtocol': protocol,
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': [{'CidrIp': f'{ip}/32'} for ip in to_authorize]
                }]
            )
        elif dir == 'egress':
            sg.authorize_egress(
                IpPermissions=[{
                    'IpProtocol': protocol,
                    'FromPort': port,
                    'ToPort': port,
                    'IpRanges': [{'CidrIp': f'{ip}/32'} for ip in to_authorize]
                }]
            )

def main():
    ec2 = boto3.resource('ec2', region_name=REGION)

    resolved_ips = resolve_ips(HOSTNAMES)
    current_sg_ips = get_sg_ips(SECURITY_GROUP_ID, PORT, PROTOCOL, ec2, 'ingress')

    if resolved_ips != current_sg_ips:
        update_sg(SECURITY_GROUP_ID, current_sg_ips, resolved_ips, PORT, PROTOCOL, ec2, 'ingress')
    
    current_sg_ips = get_sg_ips(SECURITY_GROUP_ID, PORT, PROTOCOL, ec2, 'egress')

    if resolved_ips != current_sg_ips:
        update_sg(SECURITY_GROUP_ID, current_sg_ips, resolved_ips, PORT, PROTOCOL, ec2, 'egress')
   
if __name__ == '__main__':
    main()
