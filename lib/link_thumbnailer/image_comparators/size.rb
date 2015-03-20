module LinkThumbnailer
  module ImageComparators
    class Size < ::LinkThumbnailer::ImageComparators::Base

      def call(other)
        (other.size.inject(:*)) <=> (image.size.inject(:*))
      end

    end
  end
end
