class LdapController < ApplicationController

  skip_before_filter :check_authentication

  def authenticate
    begin
      self.current_user = User.authenticate(nil, nil, servlet_request)

    rescue Exception => e
      self.current_user = nil
      Rails.logger.error(e.message)
    end
    redirect_back_or_default(home_url)
  end

end
