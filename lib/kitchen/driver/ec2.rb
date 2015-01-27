# -*- encoding: utf-8 -*-
#
# Author:: Fletcher Nichol (<fnichol@nichol.ca>)
#
# Copyright (C) 2012, Fletcher Nichol
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'benchmark'
require 'json'
require 'fog'
require 'kitchen'

module Kitchen

  module Driver

    # Amazon EC2 driver for Test Kitchen with native
    # AWS generated Windows password support
    #
    # @author Fletcher Nichol <fnichol@nichol.ca>
    class Ec2 < Kitchen::Driver::Base

      default_config :region,             'us-east-1'
      default_config :availability_zone,  'us-east-1b'
      default_config :flavor_id,          'm1.small'
      default_config :ebs_optimized,      false
      default_config :security_group_ids, ['default']
      default_config :tags,               { 'created-by' => 'test-kitchen' }
      default_config :iam_profile_name,   nil
      default_config :aws_access_key_id do |driver|
        ENV['AWS_ACCESS_KEY'] || ENV['AWS_ACCESS_KEY_ID']
      end
      default_config :aws_secret_access_key do |driver|
        ENV['AWS_SECRET_KEY'] || ENV['AWS_SECRET_ACCESS_KEY']
      end
      default_config :aws_session_token do |driver|
        ENV['AWS_SESSION_TOKEN'] || ENV['AWS_TOKEN']
      end
      default_config :aws_ssh_key_id do |driver|
        ENV['AWS_SSH_KEY_ID']
      end
      default_config :image_id do |driver|
        driver.default_ami
      end
      default_config :username do |driver|
        driver.default_username
      end
      default_config :password, ''

      default_config :endpoint do |driver|
        "https://ec2.#{driver[:region]}.amazonaws.com/"
      end

      default_config :interface, nil

      required_config :aws_access_key_id
      required_config :aws_secret_access_key
      required_config :aws_ssh_key_id
      required_config :image_id

      #Creating a new instance
      def create(state)
        return if state[:server_id]
        state[:port] = default_port
        state[:password] = config[:password] if config[:password]
        state[:username] = config[:username] if config[:username]

        server = create_server
        state[:server_id] = server.id

        info("EC2 instance <#{state[:server_id]}> created.")

        #Server preparation
        debug('Waiting for Server')
        server.wait_for { print '.'; ready? }
        print '(Server Ready)'
        state[:hostname] = hostname(server)

        #Windows preparartion
        if transport.name.casecmp('winrm') == 0
          debug("Waiting for Windows")
          $stdout.sync = true
          while !windows_ready?(state)
            putc '.'
            sleep(10)
          end
          print '(Windows Ready)'

          #If we want to use the EC2 generated Admin password
          if config[:username].casecmp('Administrator') != 0
            print("Using static credentials")
          else
            print('Fetching EC2 generated credentials')
            config[:password] = windows_password(state)
            state[:password] = config[:password]
          end
        end
        debug("Credentials: #{state[:username]} #{state[:password]}")

        debug("Waiting for transport")
        transport.connection(state) do |c|
          c.wait_for_connection
        end
        print '(Transport Ready)'


        debug("ec2:create '#{state[:hostname]}'")
      rescue Fog::Errors::Error, Excon::Errors::Error => ex
        raise ActionFailed, ex.message
      end

      #Terminating the test instance
      def destroy(state)
        return if state[:server_id].nil?

        server = connection.servers.get(state[:server_id])
        server.destroy unless server.nil?
        info("EC2 instance <#{state[:server_id]}> destroyed.")
        state.delete(:server_id)
        state.delete(:hostname)
      end

      # Helper method to map a regial AMI for the OS
      def default_ami
        region = amis['regions'][config[:region]]
        region && region[instance.platform.name.downcase]
      end

      # Helper method to choose the admin user for the OS
      def default_username
        amis['usernames'][instance.platform.name.downcase] || 'root'
      end

      private

      # Fog AWS helper method for creating connection
      def connection
        Fog::Compute.new(
        :provider               => :aws,
        :aws_access_key_id      => config[:aws_access_key_id],
        :aws_secret_access_key  => config[:aws_secret_access_key],
        :aws_session_token      => config[:aws_session_token],
        :region                 => config[:region],
        :endpoint               => config[:endpoint],
        )
      end

      # Fog AWS helper for creating the instance
      def create_server
        debug_server_config

        debug('Creating EC2 Instance..')
        connection.servers.create(
        :availability_zone         => config[:availability_zone],
        :security_group_ids        => config[:security_group_ids],
        :tags                      => config[:tags],
        :flavor_id                 => config[:flavor_id],
        :ebs_optimized             => config[:ebs_optimized],
        :image_id                  => config[:image_id],
        :key_name                  => config[:aws_ssh_key_id],
        :subnet_id                 => config[:subnet_id],
        :iam_instance_profile_name => config[:iam_profile_name],
        :user_data                 => prepared_user_data
        )
      end

      # Method for preparing user_data for enabling PS Remoting if the selected
      # transport method is WinRM

      def prepared_user_data
        if transport.name.casecmp('winrm') == 0
          debug("Injecting WinRM config to EC2 user_data")

          #Preparing custom static admin user if we defined something other than Administrator
          customAdminScript = ''
          if config[:username].casecmp('Administrator') != 0
            debug('Injecting custom Local Administrator:')
            debug("username '#{config[:username]}'")
            debug("password '#{config[:password]}'")

            customAdminScript = <<-EOH.gsub(/^ {10}/, '')
            "Disabling Complex Passwords" >> $logfile
            $seccfg = [IO.Path]::GetTempFileName()
            & secedit.exe /export /cfg $seccfg >> $logfile
            (Get-Content $seccfg) | Foreach-Object {$_ -replace "PasswordComplexity\\s*=\\s*1", "PasswordComplexity = 0"} | Set-Content $seccfg
            & secedit.exe /configure /db $env:windir\\security\\new.sdb /cfg $seccfg /areas SECURITYPOLICY >> $logfile
            & cp $seccfg "c:\\"
            & del $seccfg

            $username="#{config[:username]}"
            $password="#{config[:password]}"

            "Creating static user: $username" >> $logfile
            & net.exe user /y /add $username $password >> $logfile

            "Adding $username to Administrators" >> $logfile
            & net.exe localgroup Administrators /add $username >> $logfile

            EOH
          end

          # Returning the fully constructed PowerShell script to user_data
          return <<-EOH.gsub(/^ {10}/, '')
          <powershell>
          $logfile="C:\\Program Files\\Amazon\\Ec2ConfigService\\Logs\\kitchen-ec2.log"

          #PS Remoting and & winrm.cmd basic config
          Enable-PSRemoting -Force -SkipNetworkProfileCheck
          & winrm.cmd quickconfig -q >> $logfile
          & winrm.cmd set winrm/config '@{MaxTimeoutms="1800000"}' >> $logfile
          & winrm.cmd set winrm/config/winrs '@{MaxMemoryPerShellMB="512"}' >> $logfile
          & winrm.cmd set winrm/config/winrs '@{MaxShellsPerUser="50"}' >> $logfile

          #Client settings
          & winrm.cmd set winrm/config/client/auth '@{Basic="true"}' >> $logfile

          #Server settings
          & winrm.cmd set winrm/config/service/auth '@{Basic="true"}' >> $logfile
          & winrm.cmd set winrm/config/service '@{AllowUnencrypted="true"}' >> $logfile
          & winrm.cmd set winrm/config/winrs '@{MaxMemoryPerShellMB="1024"}' >> $logfile

          #Firewall Config
          & netsh.exe advfirewall set publicprofile state off  >> $logfile
          & netsh advfirewall firewall set rule name="Windows Remote Management (HTTP-In)" profile=public protocol=tcp localport=5985 remoteip=localsubnet new remoteip=any  >> $logfile

          #{customAdminScript}

          #{config[:user_data]}

          </powershell>
          EOH
        else
          return config[:user_data] if !config[:user_data].nil?
        end
        return ''
      end

      # Helper method to check whether Amazon reported a server Ready
      def windows_ready? state
        log = connection.get_console_output(state[:server_id]).data[:body]["output"]
        if !log.nil?
          debug("Console output: --- \n")
          debug(log)
        end
        !log.nil? and log =~ /Windows is Ready to use/
      end

      # Helper method to fetch and decrypt Windows password from EC2
      def windows_password state
        enc = connection.get_password_data(state[:server_id]).data[:body]["passwordData"].strip!
        enc = Base64.decode64(enc)
        rsa = OpenSSL::PKey::RSA.new aws_private_key
        rsa.private_decrypt(enc) if !enc.nil? and enc != ''
      rescue NoMethodError
        debug('Unable to fetch encrypted password')
        return ''
      rescue TypeError
        debug('Unable to decrypt password with AWS_PRIVATE_KEY')
        return ''
      end

      # Debug helper to display applied configuration
      def debug_server_config
        debug('EC2 Server Configuration')
        debug("ec2:region '#{config[:region]}'")
        debug("ec2:availability_zone '#{config[:availability_zone]}'")
        debug("ec2:flavor_id '#{config[:flavor_id]}'")
        debug("ec2:ebs_optimized '#{config[:ebs_optimized]}'")
        debug("ec2:image_id '#{config[:image_id]}'")
        debug("ec2:security_group_ids '#{config[:security_group_ids]}'")
        debug("ec2:tags '#{config[:tags]}'")
        debug("ec2:key_name '#{config[:aws_ssh_key_id]}'")
        debug("ec2:subnet_id '#{config[:subnet_id]}'")
        debug("ec2:iam_profile_name '#{config[:iam_profile_name]}'")
        debug("ec2:username '#{config[:username]}'")
        debug("ec2:password '#{config[:password]}'")
        debug("ec2:user_data '#{config[:user_data]}'")

      end

      # Helper method for reading the Region-OS-AMI-UserName mapings to memory
      def amis
        @amis ||= begin
          json_file = File.join(File.dirname(__FILE__),
          %w{.. .. .. data amis.json})
          JSON.load(IO.read(json_file))
        end
      end

      # Networking helper
      def interface_types
        {
          'dns' => 'dns_name',
          'public' => 'public_ip_address',
          'private' => 'private_ip_address'
        }
      end

      # Helper to get the hostname for the instance

      def hostname(server)
        if config[:interface]
          method = interface_types.fetch(config[:interface]) do
            raise Kitchen::UserError, 'Invalid interface'
          end
          server.send(method)
        else
          server.dns_name || server.public_ip_address || server.private_ip_address
        end
      end

      # Get AWS Private Key
      def aws_private_key
        begin
          ENV['AWS_PRIVATE_KEY'] || ENV['AWS_SSH_KEY'] || (File.read config[:ssh_key])
        rescue
          debug('SSH_KEY_RAW and SSH_KEY is not set.')
        end
      end

    end
  end
end
