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
      case response
      when ::Net::HTTPSuccess then decode(response['content-encoding'], response.body)
      when ::Net::HTTPRedirection
        call resolve_relative_url(response['location']), redirect_count + 1
      else
        response.error!
      end
    end

    def decode(content_encoding, body)
      if (!body) || body.empty?
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
