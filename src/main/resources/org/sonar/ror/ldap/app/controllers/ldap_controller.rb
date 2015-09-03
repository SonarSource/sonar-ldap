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

  def initUserGroups
    self.current_user ||= User.find_by_id(session[:user_id])
    if self.current_user != nil
      User.transaction do
        get_user_groups(self.current_user, servlet_request)
        self.current_user.save(false)
      end
    end

    redirect_back_or_default(home_url)
  end

  def get_user_groups(user, servlet_request)
    session = servlet_request.getSession
    if session
      windows_principal = session.getAttribute("windows_principal")
      if windows_principal
        user.groups = []
        for windows_group in windows_principal.getGroups
          group_name = windows_group.getFqn
          group = Group.find_by_name(group_name.downcase)
          if group
            user.groups << group
          end
        end
      end
    end
  end

end