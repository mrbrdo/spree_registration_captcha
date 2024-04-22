require 'recaptcha'
module SpreeRegistrationCaptcha
  module UserPasswordsControllerDecorator
    def create
      unless verify_recaptcha(action: 'signup', minimum_score: 0.7, secret_key: ENV['RECAPTCHA_SECRET_V3'])
        self.resource = resource_class.send_reset_password_instructions(params[resource_name], current_store)
        resource.errors.add(:base, 'Invalid CAPTCHA')
        respond_with_navigational(resource) { render :new, status: 422 }
      else
        super
      end
    end
  end

  module UserRegistrationsControllerDecorator
    def create
      unless verify_recaptcha(action: 'signup', minimum_score: 0.7, secret_key: ENV['RECAPTCHA_SECRET_V3'])
        @user = build_resource(spree_user_params)
        clean_up_passwords(resource)
        resource.errors.add(:base, 'Invalid CAPTCHA')
        render :new, status: 422
      else
        super
      end
    end
  end

  class Engine < Rails::Engine
    require 'spree/core'
    isolate_namespace Spree
    engine_name 'spree_registration_captcha'

    config.autoload_paths += %W(#{config.root}/lib)

    # use rspec for tests
    config.generators do |g|
      g.test_framework :rspec
    end

    def self.activate
      Spree::UserPasswordsController.prepend UserPasswordsControllerDecorator
      Spree::UserRegistrationsController.prepend UserRegistrationsControllerDecorator
    end

    config.to_prepare &method(:activate).to_proc
  end
end
