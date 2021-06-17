# frozen_string_literal: true

require 'omniauth/sberbusiness/version'
require 'omniauth'

# :nodoc:
module OmniAuth
  # :nodoc:
  module Strategies
    autoload :Sberbusiness, 'omniauth/strategies/sberbusiness'
  end
end

OmniAuth.config.add_camelization 'sberbusiness', 'Sberbusiness'
