require 'link_thumbnailer/model'
require 'link_thumbnailer/image_parser'
require 'link_thumbnailer/image_comparator'
require 'link_thumbnailer/image_validator'

module LinkThumbnailer
  module Models
    class Image < ::LinkThumbnailer::Model

      attr_reader :src, :type, :size

      def initialize(src, size = nil, type = nil)
        @src  = src
        return if !valid?
        @size = size || parser.size(self)
        @type = type || parser.type(self)
      end

      def to_s
        src.to_s
      end

      def <=>(other)
        comparator.call(other)
      end

      def valid?
        validator.call
      end

      def as_json(*)
        {
          src:  src.to_s,
          size: size,
          type: type
        }
      end

      private

      def parser
        ::LinkThumbnailer::ImageParser
      end

      def validator
        ::LinkThumbnailer::ImageValidator.new(self)
      end

      def comparator
        ::LinkThumbnailer::ImageComparator.new(self)
      end

    end
  end
end
