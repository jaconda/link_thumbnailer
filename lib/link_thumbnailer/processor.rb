require 'delegate'
require 'uri'
require 'net/http/persistent'

module LinkThumbnailer
  class Processor < ::SimpleDelegator

    attr_accessor :url
    attr_reader   :config, :http, :redirect_count

    def initialize
      @config = ::LinkThumbnailer.page.config
      @http   = ::Net::HTTP::Persistent.new

      super(config)
    end

    def call(url = '', redirect_count = 0)
      self.url        = url
      @redirect_count = redirect_count

      raise ::LinkThumbnailer::RedirectLimit if too_many_redirections?

      with_valid_url do
        set_http_headers
        set_http_options
        perform_request
      end
    end

    private

    def with_valid_url
      raise ::LinkThumbnailer::BadUriFormat unless valid_url_format?
      yield if block_given?
    end

    def set_http_headers
      http.headers['User-Agent']               = user_agent
      http.override_headers['Accept-Encoding'] = 'gzip, deflate'
    end

    def set_http_options
      http.verify_mode  = ::OpenSSL::SSL::VERIFY_NONE unless ssl_required?
      http.open_timeout = http_timeout
      http.proxy = :ENV
    end

    def perform_request
      response = http.request(url)
      return if response.content_type != "text/html"
      case response
      when ::Net::HTTPSuccess then decode(response)
      when ::Net::HTTPRedirection
        cookie = {'Cookie' => response.to_hash['set-cookie'].collect { |ea| ea[/^.*?;/]}.join }
        http.headers['Cookie'] = cookie
        call resolve_relative_url(response['location']), redirect_count + 1
      else
        response.error!
      end
    end

    def decode(response)
      content_encoding, body = response['content-encoding'], response.body

      decoded_body = if (!body) || body.empty?
        body
      elsif content_encoding == 'gzip'
        Zlib::GzipReader.new(StringIO.new(body)).read
      elsif content_encoding == 'deflate'
        begin
          Zlib::Inflate.new.inflate body
        rescue Zlib::DataError
          # No luck with Zlib decompression. Let's try with raw deflate,
          # like some broken web servers do.
          Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate body
        end
      else
        body
      end

      encoding = get_encoding_from_headers(response['content-type'])
      if !encoding
        # trying to find encoding in meta tags
        document = ::Nokogiri::HTML(decoded_body)
        if document.meta_encoding
          encoding = document.meta_encoding
        else
          encoding = 'ISO-8859-1'
        end
      end
      decoded_body.force_encoding(encoding).encode('UTF-8')
    end

    # Return encoding from an HTTP header hash.
    #
    # @param headers [Hash]
    #
    # @return [String] encoding
    #
    def get_encoding_from_headers(type_header)
      return nil unless type_header

      content_type, params = cgi_parse_header(type_header)

      if params.include?('charset')
        return params.fetch('charset').gsub(/(\A["']*)|(["']*\z)/, '')
      end

      nil
    end

    # Parse semi-colon separated, potentially quoted header string iteratively.
    #
    # @private
    #
    def _cgi_parseparam(s)
      return enum_for(__method__, s) unless block_given?

      while s[0] == ';'
        s = s[1..-1]
        ends = s.index(';')
        while ends && ends > 0 \
              && (s[0...ends].count('"') -
                  s[0...ends].scan('\"').count) % 2 != 0
          ends = s.index(';', ends + 1)
        end
        if ends.nil?
          ends = s.length
        end
        f = s[0...ends]
        yield f.strip
        s = s[ends..-1]
      end
      nil
    end

    # Parse a Content-type like header.
    #
    # Return the main content-type and a hash of options.
    #
    # This method was ported directly from Python's cgi.parse_header(). It
    # probably doesn't read or perform particularly well in ruby.
    # https://github.com/python/cpython/blob/3.4/Lib/cgi.py#L301-L331
    #
    #
    # @param [String] line
    # @return [Array(String, Hash)]
    #
    def cgi_parse_header(line)
      parts = _cgi_parseparam(';' + line)
      key = parts.next
      pdict = {}

      begin
        while p = parts.next
          i = p.index('=')
          if i
            name = p[0...i].strip.downcase
            value = p[i+1..-1].strip
            if value.length >= 2 && value[0] == '"' && value[-1] == '"'
              value = value[1...-1]
              value = value.gsub('\\\\', '\\').gsub('\\"', '"')
            end
            pdict[name] = value
          end
        end
      rescue StopIteration
      end

      [key, pdict]
    end

    def resolve_relative_url(location)
      location.start_with?('http') ? location : build_absolute_url_for(location)
    end

    def build_absolute_url_for(relative_url)
      URI("#{url.scheme}://#{url.host}#{relative_url}")
    end

    def redirect_limit
      config.redirect_limit
    end

    def user_agent
      config.user_agent
    end

    def http_timeout
      config.http_timeout
    end

    def ssl_required?
      config.verify_ssl
    end

    def too_many_redirections?
      redirect_count > redirect_limit
    end

    def valid_url_format?
      url.is_a?(::URI::HTTP)
    end

    def url=(url)
      @url = ::URI.parse(url.to_s)
    end

  end
end
