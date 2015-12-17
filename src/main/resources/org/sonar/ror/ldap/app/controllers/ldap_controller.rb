#
# SonarQube LDAP Plugin
# Copyright (C) 2009 SonarSource
# dev@sonar.codehaus.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02
#

class LdapController < ApplicationController

  skip_before_filter :check_authentication, :set_user_session

  def validate
    begin
      self.current_user = User.authenticate(nil, nil, servlet_request)
    rescue Exception => e
      self.current_user = nil
      Rails.logger.error(e.message)
    end
    redirect_back_or_default(home_url)
  end

  def logout
    if logged_in?
      self.current_user.on_logout
      self.current_user.forget_me
    end
    cookies.delete :auth_token
    redirect_to("/sessions/login")
    reset_session
  end
end