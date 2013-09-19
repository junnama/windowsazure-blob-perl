use strict;
use warnings;
package WindowsAzure::Blob;
{
  $WindowsAzure::Blob::VERSION = '0.14';
}
use LWP::UserAgent;
use HTTP::Date;
use URI::QueryParam;
use MIME::Base64;
use Digest::SHA qw( hmac_sha256_base64 );
use Data::Dumper;

sub new {
    my $class = shift;
    my $obj = bless {}, $class;
    $obj->init( @_ );
}

sub init {
    my $this = shift;
    my %args = @_;
    $this->{ account_name } = $args{ account_name };
    $this->{ primary_access_key } = $args{ primary_access_key };
    my $container_name = $args{ container_name };
    if ( $container_name ) {
        $container_name =~ s!/!!g;
        $this->{ container_name } = $container_name;
    }
    $this->{ api_version } = $args{ api_version } || '2012-02-12';
    $this->{ schema } = $args{ schema } || 'https';
    return $this;
}

sub sign {
    my $blob = shift;
    my ( $req, $params ) = @_;
    my $key = $blob->{ primary_access_key };
    my $api_version = $blob->{ api_version };
    $req->header( 'x-ms-version', $api_version );
    $req->header( 'x-ms-date', HTTP::Date::time2str() );
    if ( $params && ( my $headers = $params->{ headers } ) ) {
        for my $key ( keys %$headers ) {
            $req->header( $key, $headers->{ $key } );
        }
    }
    my $canonicalized_headers = join '', map { lc( $_ ) . ':' .
       $req->header( $_ ) . "\n" } sort grep { /^x-ms/ } keys %{ $req->headers };
    my $account = $req->uri->authority;
    $account =~ s/^([^.]*).*$/$1/;
    my $path = $req->uri->path;
    my $canonicalized_resource = "/${account}${path}";
    $canonicalized_resource .= join '', map { "\n" . lc( $_ ) . ':' .
        join( ',', sort $req->uri->query_param( $_ ) ) }
            sort $req->uri->query_param;
    my $method = $req->method;
    my $encoding = $req->header( 'Content-Encoding' ) || '';
    my $language = $req->header( 'Content-Language' ) || '';
    my $length = $req->header( 'Content-Length' );
    if (! defined $length ) {
        $length = '';
    }
    my $md5 = $req->header( 'Content-MD5' ) || '';
    my $content_type = $req->header( 'Content-Type' ) || '';
    my $date = $req->header( 'Date' ) || '';
    my $if_mod_since = $req->header( 'If-Modified-Since' ) || '';
    my $if_match = $req->header( 'If-Match' ) || '';
    my $if_none_match = $req->header( 'If-None-Match' ) || '';
    my $if_unmod_since = $req->header( 'If-Unmodified-Since' ) || '';
    my $range = $req->header( 'Range' ) || '';
    my @headers = ( $method, $encoding, $language, $length, $md5, $content_type, $date,
                    $if_mod_since, $if_match, $if_none_match, $if_unmod_since, $range );
    push ( @headers, "${canonicalized_headers}${canonicalized_resource}" );
    my $string_to_sign = join( "\n", @headers );
    # print $string_to_sign;
    my $signature = hmac_sha256_base64( $string_to_sign, decode_base64( $key ) );
    $signature .= '=' x ( 4 - ( length( $signature ) % 4 ) );
    $req->authorization( "SharedKey ${account}:${signature}" );
    return $req;
}

sub create_container {
    my $blob = shift;
    my $account = $blob->{ account_name };
    my ( $name, $params ) = @_;
    $name =~ s!^/!!;
    my $data = 'restype=container';
    my $schema = $blob->{ schema };
    my $url = "${schema}://${account}.blob.core.windows.net/${name}?${data}";
    my $req = new HTTP::Request( 'PUT' => $url );
    $req->content_length( length( $data ) );
    $req = $blob->sign( $req, $params );
    $req->content( $data );
    my $ua = LWP::UserAgent->new;
    return $ua->request( $req );
}

sub get {
    my $blob = shift;
    my $account = $blob->{ account_name };
    my ( $path, $params ) = @_;
    $path =~ s!^/!!;
    if ( my $container_name = $blob->{ container_name } ) {
        $path = $container_name . '/' . $path;
    }
    my $filename;
    if ( $params && $params->{ filename } ) {
        $filename = $params->{ filename };
    }
    my $schema = $blob->{ schema };
    my $request_type = $params->{ request_type } || 'GET';
    my $url = "${schema}://${account}.blob.core.windows.net/${path}";
    my $req = new HTTP::Request( $request_type, $url );
    $req = $blob->sign( $req, $params );
    my $ua = LWP::UserAgent->new;
    my $res = $ua->request( $req );
    if ( $filename ) {
        if ( $res->code == 200 ) {
            my $content = $res->content;
            require File::Basename;
            my $dir = File::Basename::dirname( $filename );
            if (! -d $dir ) {
                require File::Path;
                File::Path::mkpath( $dir );
            }
            if (-d $dir ) {
                open my $fh, ">$filename" or die "Can't open '$filename'.";
                print $fh $content;
                close $fh ; 
            }
        }
    }
    return $res;
}

sub get_metadata {
    my $blob = shift;
    my ( $path, $params ) = @_;
    $params->{ request_type } = 'HEAD';
    return $blob->get( $path, $params );
}

sub set_metadata {
    my $blob = shift;
    my $account = $blob->{ account_name };
    my ( $path, $params ) = @_;
    $path =~ s!^/!!;
    if ( my $container_name = $blob->{ container_name } ) {
        $path = $container_name . '/' . $path;
    }
    my $data = 'comp=metadata';
    my $schema = $blob->{ schema };
    my $url = "${schema}://${account}.blob.core.windows.net/${path}?${data}";
    my $req = new HTTP::Request( 'PUT' => $url );
    my $metadata = $params->{ metadata };
    for my $key ( keys %$metadata ) {
        my $meta = $key;
        if ( $key !~ m/^x\-ms\-meta\-/ ) {
            $meta = 'x-ms-meta-' . $meta;
        }
        $req->header( $meta, $metadata->{ $key } );
    }
    $req->content_length( length( $data ) );
    $req = $blob->sign( $req, $params );
    $req->content( $data );
    my $ua = LWP::UserAgent->new;
    return $ua->request( $req );
}

sub put {
    my $blob = shift;
    my $account = $blob->{ account_name };
    my ( $path, $data, $params ) = @_;
    $path =~ s!^/!!;
    if ( my $container_name = $blob->{ container_name } ) {
        $path = $container_name . '/' . $path;
    }
    if ( ref $data eq 'HASH' ) {
        $params = $data;
    }
    my $schema = $blob->{ schema };
    my $url = "${schema}://${account}.blob.core.windows.net/${path}";
    my $req = new HTTP::Request( 'PUT', $url );
    $req->header( 'x-ms-blob-type', 'BlockBlob' );
    if ( $params && $params->{ filename } ) {
        $data = '';
        my $filename = $params->{ filename };
        # $req->content_length( -s $filename );
        open my $fh, "<$filename" or die "Can't open '$filename'.";
        binmode $fh;
        while ( read $fh, my ( $chunk ), 8192 ) {
            $data .= $chunk;
        }
        close $fh;
        if (! $params->{ no_attributes } ) {
            my @stats = stat $filename;
            $req->header( 'x-ms-meta-mode', sprintf( '%o', $stats[ 2 ] ) ); # oct()
            $req->header( 'x-ms-meta-uid', $stats[ 4 ] );
            $req->header( 'x-ms-meta-gid', $stats[ 5 ] );
            $req->header( 'x-ms-meta-mtime', $stats[ 9 ] );
                        # Custom header for set timestamp and permission.
        }
    }
    $req->content_length( length $data );
    $req = $blob->sign( $req, $params );
    $req->content( $data );
    my $ua = LWP::UserAgent->new;
    return $ua->request( $req );
}

sub upload {
    my $blob = shift;
    my ( $path, $filename, $params ) = @_;
    $params->{ filename } = $filename;
    return $blob->put( $path, $params );
}

sub copy {
    my $blob = shift;
    my $account = $blob->{ account_name };
    my ( $src, $path, $params ) = @_;
    $src =~ s!^/!!;
    $path =~ s!^/!!;
    if ( my $container_name = $blob->{ container_name } ) {
        $src = $container_name . '/' . $src;
        $path = $container_name . '/' . $path;
    }
    my $timeout = $params->{ timeout } || 180;
    $timeout = 'timeout=' . $timeout;
    my $schema = $blob->{ schema };
    my $url = "${schema}://${account}.blob.core.windows.net/${path}";
    my $src_url = "${schema}://${account}.blob.core.windows.net/${src}";
    my $req = new HTTP::Request( 'PUT' => $url );
    $req->header( 'x-ms-copy-source', $src_url );
    $req->content_length( length( $timeout ) );
    $req = $blob->sign( $req, $params );
    $req->content( $timeout );
    my $ua = LWP::UserAgent->new;
    return $ua->request( $req );
}

sub rename {
    my $blob = shift;
    my ( $src, $path, $params ) = @_;
    my $res = $blob->copy( $src, $path, $params );
    $blob->remove( $src );
    return $res;
}

sub download {
    my $blob = shift;
    my $account = $blob->{ account_name };
    my ( $path, $filename, $params ) = @_;
    $params->{ filename } = $filename;
    return $blob->get( $path, $params );
}

sub remove {
    my $blob = shift;
    my $account = $blob->{ account_name };
    my ( $path, $params ) = @_;
    $path =~ s!^/!!;
    if ( my $container_name = $blob->{ container_name } ) {
        $path = $container_name . '/' . $path;
    }
    my $schema = $blob->{ schema };
    my $url = "${schema}://${account}.blob.core.windows.net/${path}";
    my $req = new HTTP::Request( 'DELETE', $url );
    $req = $blob->sign( $req, $params );
    my $ua = LWP::UserAgent->new;
    return $ua->request( $req );
}

sub list {
    my $blob = shift;
    my $account = $blob->{ account_name };
    my ( $path, $params ) = @_;
    $path = '' unless $path;
    $path =~ s!^/!!;
    my $schema = $blob->{ schema };
    my $url = "${schema}://${account}.blob.core.windows.net/${path}";
    if ( $path ) {
        $url .= '?restype=container&comp=list';
    } else {
        $url .= '?comp=list';
    }
    my $req = new HTTP::Request( 'GET', $url );
    $req = $blob->sign( $req, $params );
    my $ua = LWP::UserAgent->new;
    return $ua->request( $req );
}

1;

__END__

=head1 NAME

WindowsAzure::Blob - Interface to Windows Azure Blob Service

=head1 SYNOPSIS

  my $blob = WindowsAzure::Blob->new( account_name => $you_account_name,
                                      primary_access_key => $your_primary_access_key,
                                      [ container_name => $container_name, ]
                                      [ schema => 'https', ] );
  my $path = 'path/to/file';
  my $res = $blob->get( $path );

  my $params = { headers => { 'x-ms-foo' => 'bar' } };
  my $res = $blob->get( $path, $params ); # Request with custom http headers
  
  # return HTTP::Response object

=head1 METHODS

=head2 create_container

The Create Container operation creates a new container under the specified account.
If the container with the same name already exists, the operation fails.
http://msdn.microsoft.com/en-us/library/windowsazure/dd179468.aspx

  my $res = $blob->create_container( $container_name );

=head2 get

The Get Blob operation reads or downloads a blob from the system.
http://msdn.microsoft.com/en-us/library/windowsazure/dd179440.aspx

  my $res = $blob->get( $path );

  my $params = { filename => '/path/to/filename' };
  my $res = $blob->get( $path, $params );  # Get blob and save file

=head2 get_metadata

The Get Blob Metadata operation returns all user-defined metadata for the specified blob
http://msdn.microsoft.com/en-us/library/windowsazure/dd179350.aspx

  my $res = $blob->get_metadata( $path );

=head2 download

Download a blob to local file.

  my $res = $blob->download( $path, $filename );

=head2 put

The Put Blob operation creates a new block blob, or updates the content of an existing block blob.
http://msdn.microsoft.com/en-us/library/windowsazure/dd179451.aspx

  my $res = $blob->put( $path, $content );  # Put content to blob

  my $params = { filename => '/path/to/filename' };
  my $res = $blob->put( $path, $params ); # Put local file to blob

=head2 upload

Upload a new block blob from local file.

  my $res = $blob->upload( $path, $filename );

=head2 set_metadata

The Set Blob Metadata operation sets user-defined metadata for the specified blob as one or more name-value pairs.
http://msdn.microsoft.com/en-us/library/windowsazure/dd179414.aspx

  my $params = { metadata => { category => 'image'
                               author => $author_name } };
  my $res = $blob->get_metadata( $path, $params );
  # Set x-ms-meta-category and x-ms-meta-author metadata.

=head2 remove

The Delete Blob operation marks the specified blob.
http://msdn.microsoft.com/en-us/library/windowsazure/dd179413.aspx

  my $res = $blob->remove( $path );

=head2 copy

The Copy Blob operation copies a blob to a destination within the storage account.
http://msdn.microsoft.com/en-us/library/windowsazure/dd894037.aspx

  my $res = $blob->copy( $from, to );

=head2 rename

The Rename Blob operation rename a blob to a destination within the storage account.
http://msdn.microsoft.com/en-us/library/windowsazure/dd894037.aspx

  my $res = $blob->rename( $from, to ); # Copy and remove blob

=head2 list

The List Blobs operation enumerates the list of blobs under the specified container.
http://msdn.microsoft.com/en-us/library/windowsazure/dd135734.aspx

  my $res = $blob->list( $container ); # List blobs of container
  my $res = $blob->list(); # List containers

=head1 AUTHOR

Junnama Noda <junnama@alfasado.jp>

=head1 COPYRIGHT

Copyright (C) 2013, Junnama Noda.

=head1 LICENSE

This program is free software;
you can redistribute it and modify it under the same terms as Perl itself.

=cut
