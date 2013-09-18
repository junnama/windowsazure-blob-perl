#!/usr/bin/perl -w
use strict;
use lib qw( lib );
use Test::More tests => 11;

my $res;
my $error = 0;
use_ok( 'WindowsAzure::Blob' );

print "Enter account_name:";
my $account_name = <STDIN>;
chomp( $account_name );
print "Enter primary_access_key:";
my $primary_access_key = <STDIN>;
chomp( $primary_access_key );
print "Enter container name:\n";
my $container = <STDIN>;
chomp( $container );

my $blob = WindowsAzure::Blob->new( account_name => $account_name,
                                    primary_access_key => $primary_access_key,
                                    container_name => $container );

isa_ok $blob, 'WindowsAzure::Blob';

if ( (! $account_name ) || (! $primary_access_key ) || (! $container ) ) {
    die "account_name, primary_access_key and container_name are required."
}

# list(containers)
$res = $blob->list();
if ( is $res->code, 200 ) {
    print "Get List containers succesfull.\n";
} else {
    $error++;
}

# list(blobs of container)
$res = $blob->list( $container );
if ( is $res->code, 200 ) {
    print "Get List of container ${container} succesfull.\n";
} else {
    $error++;
}

# get
print "Enter path/to/blob_name to get:\n";
my $path = <STDIN>;
chomp( $path );
$res = $blob->get( $path );
if ( is $res->code, 200 ) {
    print "Get ${path} succesfull.\n";
} else {
    $error++;
}

# copy
print "Enter path/to/blob_name to copy:\n";
my $copy_to = <STDIN>;
chomp( $copy_to );
$res = $blob->copy( $path, $copy_to );
if ( is $res->code, 202 ) {
    print "Copy from ${path} to ${copy_to} succesfull.\n";
} else {
    $error++;
}

# remove
$res = $blob->remove( $copy_to );
if ( is $res->code, 202 ) {
    print "Remove ${copy_to} succesfull.\n";
} else {
    $error++;
}

# rename
print "Enter path/to/blob_name to move:\n";
my $move_to = <STDIN>;
chomp( $move_to );
$res = $blob->rename( $path, $move_to );
if ( is $res->code, 202 ) {
    print "Rename from ${path} to ${move_to} succesfull.\n";
    # $blob->rename( $move_to, $path );
} else {
    $error++;
}

# put
print "Enter path to path/to/blob_name to put:\n";
my $put_to = <STDIN>;
chomp( $put_to );
print "Enter content to put:\n";
my $content = <STDIN>;
chomp( $content );
$content = 'This is test.' unless $content;
$res = $blob->put( $put_to, $content );
if ( is $res->code, 201 ) {
    print "Put ${put_to} succesfull.\n";
} else {
    $error++;
}

# download
print "Enter filename to download:\n";
my $filename = <STDIN>;
chomp( $filename );
$res = $blob->download( $put_to, $filename );
if ( is $res->code, 200 ) {
    print "Download ${put_to} succesfull.\n";
} else {
    $error++;
}

# upload
print "Enter path/to/blob_name to upload:\n";
my $upload_path = <STDIN>;
chomp( $upload_path );
$upload_path = 'test/test-folder/upload_test.txt' unless $upload_path;
$res = $blob->upload( $upload_path, $filename );
if ( is $res->code, 201 ) {
    print "Upload ${upload_path} succesfull.\n";
} else {
    $error++;
}

if ( $error ) {
    print "${error} errors were found.\n";
} else {
    print "No error was found.\n";
}

done_testing;