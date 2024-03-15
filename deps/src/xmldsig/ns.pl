#!/usr/bin/perl

use lib ".";
use Data::Dumper;
use xmldsig;

my %params;

$params{template} = <<'END_MESSAGE';
<?xml version="1.0" encoding="utf-8"?>
<Document xmlns="http://cyberft.ru/xsd/cftdoc.01"><Header><DocId>026AAED6-7BC9-11E5-898C-74D435BBCFAA</DocId><DocDate>2015-10-26T13:04:56+03:00</DocDate><SenderId>ZUZRUMMAXXXX</SenderId><ReceiverId>ZUZRUMMAXXXX</ReceiverId><DocType>MT999</DocType></Header><Body mimeType="application/text">
<SignedData xmlns="http://cyberft.ru/xsd/cftdata.02">
  <Content>
    <RawData Id="id457845" mimeType="application/xml" encoding="base64" filename="test.swa" RegisterId="324678" RegisterDate="2015-08-25T10:24:06Z">77u/AXsxOkYwMUNZQ1BSVU1AQVpBTzAwMDAwMDAwMDB9ezI6STEwM1BMQVRSVU1N QVhYWE59ezQ6DQo6MjA6KzAwMDAwMDAwMDAwMA0KOjIzQjpDUkVEDQo6MjZUOjAx DQo6MzJBOjE0MTIxOFJVQjEwMDAsMDANCjo1MEE6LzQwNzEwODIzMjMwMDUwMDY0 NTEyDQpJTk43NzIxMDQ5OTA0LktQUDc3MjEwMTAwMQ0KT09PIG1LT05GRVRQUk9N bQ0KOjU3RDovL1JVMDAwMDAwMDAzLjMwMTAxODEwMTAwMDAwMDAwNzc0DQpBS0Ig bUFWVC1CQU5LbSBHLk1PU0tWQQ0KOjU5QTovODg4ODg4ODk5OTk5OTk5OTk5OTkN CklOTjc3MjMwNTA5MTYuS1BQNzcyMzAxMDAxDQpVRksgTUYgUkYgUE8gRy4gTU9T S1ZFIChJRk5TIFJGIG4gMjMgUE8gdVZBTyBHLiBNT1NLVlksIEwvUyAgNDAxMDA3 NzAwMjMpDQo6NzFBOk9VUg0KOjcyOi9SUFAvMy4xNDEyMTguNS5FTEVLLi4wMQ0K L05aUC9vaUNVS0VOR1FxWkh4RllWQVBST0xESmVhY1NNSVRYQnVvaUNVS0VOR1Fx Wkh4RllWQVBST0xESmVhY1NNSVRYQnVqZmJmbnNwZmRmKCl6Ky1ybm0oKSgpai8v Lz92DQo6NzdCOi9OMTAvMC9ONC8wNzYxMDEwMTAyMDAxMTAwMDExMA0KL041LzEx MzExMTExMTExL042L1RQL043L01TLjEyLjIwMTQNCi9OOC8wL045LzANCi19ezU6 e01BQzowMDAwMDAwMH17Q0hLOjAwMDAwMDAwMDAwMH19Aw0K</RawData>
</Content>
<Signatures>
	<Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Id="id_1426754597374">
	<SignedInfo>
		<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411"/>
        <Reference URI="#id457845">
            <DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr3411"/>
		<DigestValue></DigestValue>
		</Reference>
	</SignedInfo>
	<SignatureValue></SignatureValue>
	<KeyInfo>
		<X509Data><X509SubjectName></X509SubjectName></X509Data>
		<KeyName></KeyName>
	</KeyInfo>
	</Signature>
</Signatures>
</SignedData></Body></Document>

END_MESSAGE



# sign GOST

$params{xmlns} = {
   "ds" => "http://www.w3.org/2000/09/xmldsig#"
};

$params{sigpath} = "//ds:Signature";
$params{cert} = 'roskazna/cert.pem';
$params{key} = 'roskazna/key.pem';
$params{pwd} = 'cyber2015';

$out = sign(\%params);
print "sign: \t".Dumper($out)."\n";


#verify GOST

open FILE, $params{cert} or die "Couldn't open file: $!"; 
$s = join("", <FILE>); 
close FILE;
$params{cert} = $s;

#$params{xsd} = "";
$params{sigpath} = "//*[local-name()='Signature']";
$params{xml} = $out->{xml};
print "verify: \t".Dumper(verify(\%params))."\n";


