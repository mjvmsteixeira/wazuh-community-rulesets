"""Nomes de campo dos decoders (<order>) -> campo ECS sugerido, para correlação e para a migração para o Wazuh 5.0.

A chave é o nome normalizado (minúsculas, sem '_', '-', '.'); cobre os campos estáticos da Wazuh e as variantes mais comuns.
"""
import re

ECS = {
    'srcip': 'source.ip', 'sourceip': 'source.ip', 'srcaddr': 'source.ip', 'sourceaddress': 'source.ip', 'src': 'source.ip', 'clientip': 'source.ip',
    'remoteip': 'source.ip', 'remoteaddr': 'source.ip',
    'dstip': 'destination.ip', 'destip': 'destination.ip', 'destinationip': 'destination.ip', 'dstaddr': 'destination.ip', 'dst': 'destination.ip',
    'destinationaddress': 'destination.ip', 'serverip': 'destination.ip',
    'srcport': 'source.port', 'sourceport': 'source.port', 'sport': 'source.port', 'clientport': 'source.port',
    'dstport': 'destination.port', 'destport': 'destination.port', 'destinationport': 'destination.port', 'dport': 'destination.port',
    'srcmac': 'source.mac', 'mac': 'source.mac', 'dstmac': 'destination.mac',
    'srcuser': 'source.user.name', 'user': 'user.name', 'username': 'user.name', 'usr': 'user.name', 'account': 'user.name', 'login': 'user.name',
    'dstuser': 'user.target.name', 'targetuser': 'user.target.name',
    'protocol': 'network.transport', 'proto': 'network.transport', 'action': 'event.action', 'status': 'event.outcome', 'result': 'event.outcome',
    'id': 'event.code', 'eventid': 'event.code', 'severity': 'event.severity', 'level': 'log.level', 'message': 'message', 'msg': 'message',
    'url': 'url.original', 'uri': 'url.original', 'method': 'http.request.method', 'httpmethod': 'http.request.method',
    'useragent': 'user_agent.original', 'statuscode': 'http.response.status_code', 'httpstatus': 'http.response.status_code',
    'hostname': 'host.name', 'host': 'host.name', 'devname': 'observer.name', 'device': 'observer.name', 'systemname': 'host.name',
    'process': 'process.name', 'processname': 'process.name', 'program': 'process.name', 'pid': 'process.pid', 'ppid': 'process.parent.pid',
    'commandline': 'process.command_line', 'cmd': 'process.command_line', 'command': 'process.command_line',
    'file': 'file.path', 'filename': 'file.name', 'path': 'file.path', 'md5': 'file.hash.md5', 'sha1': 'file.hash.sha1', 'sha256': 'file.hash.sha256',
    'hash': 'file.hash.sha256', 'domain': 'destination.domain', 'query': 'dns.question.name', 'qname': 'dns.question.name',
    'interface': 'observer.ingress.interface.name', 'srcintf': 'observer.ingress.interface.name', 'dstintf': 'observer.egress.interface.name',
    'policy': 'rule.name', 'policyid': 'rule.id', 'rule': 'rule.name', 'sessionid': 'network.session_id', 'session': 'network.session_id',
    'bytes': 'network.bytes', 'sentbyte': 'source.bytes', 'rcvdbyte': 'destination.bytes', 'service': 'network.protocol', 'app': 'network.application',
    'country': 'source.geo.country_name', 'srccountry': 'source.geo.country_name', 'dstcountry': 'destination.geo.country_name',
    'timestamp': '@timestamp', 'date': '@timestamp', 'time': '@timestamp', 'extradata': 'event.original', 'data': 'event.original',
    'description': 'event.reason', 'reason': 'event.reason', 'type': 'event.type', 'subtype': 'event.type', 'category': 'event.category',
    'vendor': 'observer.vendor', 'product': 'observer.product', 'productname': 'observer.product', 'version': 'observer.version',
}
STATIC = {'srcip', 'dstip', 'srcport', 'dstport', 'protocol', 'action', 'id', 'url', 'data', 'extra_data', 'status', 'srcuser', 'dstuser', 'system_name', 'user'}

def key(field):
    last = field.split('.')[-1]
    return re.sub(r'[^a-z0-9]', '', last.lower())

def ecs(field):
    if field.startswith(('source.', 'destination.', 'user.', 'event.', 'host.', 'process.', 'file.', 'network.', 'url.', 'http.', 'observer.')):
        return field   # já em ECS
    return ECS.get(key(field), '')
