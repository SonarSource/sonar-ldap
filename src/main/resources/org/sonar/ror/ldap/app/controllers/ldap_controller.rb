class LdapController < ApplicationController

  skip_before_filter :check_authentication

  def validate
    begin
      self.current_user = User.authenticate(nil, nil, servlet_request)

    rescue Exception => e
      self.current_user = nil
      Rails.logger.error(e.message)
    end
    redirect_back_or_default(home_url)
  end

  def unauthorized
    # this page should be moved to sonar core
    params[:layout]='false'
    render :action => 'unauthorized'
  end

end
