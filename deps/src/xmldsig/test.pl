#!/usr/bin/perl

use lib ".";
use Data::Dumper;
use xmldsig;

my %params;

$params{template} = <<'END_MESSAGE';
<msg xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<header>
<hdr_param1>header param 1</hdr_param1>
<hdr_param2>header param 2</hdr_param2>
<hdr_param3>header param 3</hdr_param3>

<ds:Signature>
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<ds:Reference URI="">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
<ds:XPath xmlns:target_prefix="urn:iso:std:iso:20022:tech:xsd:pain.001.002.05">ancestor-or-self::target_prefix:Document</ds:XPath>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue></ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue></ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data><ds:X509SubjectName></ds:X509SubjectName></ds:X509Data>
<ds:KeyName></ds:KeyName>
</ds:KeyInfo>
</ds:Signature>

<ds:Signature>
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
<ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
<ds:Reference URI="">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
<ds:XPath xmlns:target_prefix="urn:iso:std:iso:20022:tech:xsd:pain.001.002.05">ancestor-or-self::target_prefix:Document</ds:XPath>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
<ds:DigestValue></ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue></ds:SignatureValue>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509SubjectName></ds:X509SubjectName>
</ds:X509Data>
<ds:KeyName>i
</ds:KeyName>
</ds:KeyInfo>
</ds:Signature>

<ds:Signature>
<ds:SignedInfo>
<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411"/>
<ds:Reference URI="">
<ds:Transforms>
<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
<ds:XPath xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">not(ancestor-or-self::dsig:Signature)</ds:XPath>
</ds:Transform>
</ds:Transforms>
<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr3411"/>
<ds:DigestValue></ds:DigestValue>
</ds:Reference>
</ds:SignedInfo>
<ds:SignatureValue/>
<ds:KeyInfo>
<ds:X509Data>
<ds:X509Certificate></ds:X509Certificate>
</ds:X509Data>
</ds:KeyInfo>
</ds:Signature>

</header>
<body>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pain.001.002.05">
<param1>param 1</param1>
<param2>param 2</param2>
<param3>param 3</param3>
</Document>
</body>
</msg>

END_MESSAGE


#for ($i=0; $i<5000; $i++) {

#sign RSA

#$params{sigpath} = "//*[local-name()='Signature']";
$params{sigpath} = "//*[local-name()='Signature'][2]";
$params{cert} = 'certs/test.cer';
$params{key} = 'certs/test.key';
$params{pwd} = 'test';

$out = sign(\%params);
print "sign: \t".Dumper($out)."\n";


#verify RSA

open FILE, $params{cert} or die "Couldn't open file: $!"; 
$s = join("", <FILE>); 
close FILE;
$params{cert} = $s;

#$params{xsd} = "";
$params{sigpath} = "//*[local-name()='Signature'][2]";
$params{xml} = $out->{xml};
print "verify: \t".Dumper(verify(\%params))."\n";


# sign GOST

$params{sigpath} = "//*[local-name()='Signature'][3]";
$params{cert} = 'certs/gosttest.cer';
$params{key} = 'certs/gosttest.key';
$params{pwd} = 'test';

$out = sign(\%params);
print "sign: \t".Dumper($out)."\n";


#verify GOST

open FILE, $params{cert} or die "Couldn't open file: $!"; 
$s = join("", <FILE>); 
close FILE;
$params{cert} = $s;

#$params{xsd} = "";
$params{sigpath} = "//*[local-name()='Signature'][3]";
$params{xml} = $out->{xml};
print "verify: \t".Dumper(verify(\%params))."\n";

#}


