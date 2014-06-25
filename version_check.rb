require 'yaml'
require 'yaml/store'
require 'logger'
require 'tempfile'
require 'nokogiri'
require 'pp'
require 'json'
require 'getoptlong'
require 'date'
require 'erb'
require 'net/smtp'

module QueryAPIs
  PACKAGE_HTML = "curl -k -sS --user ':' --negotiate 'https://errata.devel.redhat.com/package/show/%s'"
  ADVISORY_JSON = "curl -k -sS --user ':' --negotiate 'https://errata.devel.redhat.com/advisory/%s.json'"
  ADVISORY_HTML = "curl -k -sS --user ':' --negotiate 'https://errata.devel.redhat.com/advisory/%s'"
  RELEASE_JSON = "curl -k -sS --user ':' --negotiate 'https://errata.devel.redhat.com/release/%s.json'"
end

class MultiIO
  def initialize(*targets)
    @targets = targets
  end

  def write(*args)
    @targets.each {|t| t.write(*args)}
  end

  def close
    @targets.each(&:close)
  end
end

def get_logger
  log = Logger.new(STDOUT)
  file = File.open('details.log', File::WRONLY | File::CREAT | File::TRUNC)
  log = Logger.new MultiIO.new(STDOUT, file)
end

$log = get_logger
$log.formatter = proc do |severity, datetime, progname, msg|
  "#{severity}:: #{msg}\n"
end

class QueryErrata

  def self.query_for_raw_html(package_name)
    cmd = QueryAPIs::PACKAGE_HTML % package_name
    $log.info cmd
    #TODO handle connection error
    r_val = `#{cmd}`

    if r_val.include? 'Authorization Required'
      warn_msg = "You need to use 'kinit id@REDHAT.COM to get a vaild ticket'"
      $log.error '!' * warn_msg.length
      $log.error warn_msg
      $log.error '!' * warn_msg.length
      exit -1
    end

    if block_given?
      yield r_val
    else
      r_val
    end
  end

  def self.get_release_date_f_html(errata_id)
    cmd = QueryAPIs::ADVISORY_HTML % errata_id
    r_val = `#{cmd}`
    release_date = nil
    page = Nokogiri::HTML(r_val)
    details = page.search('td[text()="Release date"] ~ *')
    details.each do |x|
      if x.text =~ /\d{4}-[a-zA-Z]{3}-\d{2}/
        release_date = Date.parse(x.text)
      elsif x.text =~ /ASAP/
        release_date = 'ASAP'
      end
    end
    yield release_date
  end

  def self.get_release_date_f_release(release_id)
    cmd = QueryAPIs::RELEASE_JSON % release_id
    r_val = `#{cmd}`
    yield JSON.parse(r_val)['ship_date']
  end

  def self.parse_raw_html(html, release_name)
    results = {:active_errata => [], :shipped_errata => []}
    page = Nokogiri::HTML(html)
    page.css('//tbody').each_with_index  do |tb ,index|
      $log.info 'Start to parsing data from errata table'
      tb.css('tr').each do |tr|
        row = []
        tr.css('/td').each do |td|
          if td.children[0].attr('class') == 'advisory_link'
            row.push td.children.attr('href').value.split('/')[-1]
          else
            row.push td.children.text
          end
        end
        if index == 0
          results[:active_errata].push row if row[2].include? "#{release_name}"
        else
          results[:shipped_errata].push row if row[3].include? "#{release_name}"
        end
      end
    end

    results
  end

  def self.release_date_of_each_advisory!(res)

    res.each_key do |key|
      res[key].each do |errata|
        r_url = QueryAPIs::ADVISORY_JSON % errata[0]
        r_val = `#{r_url}`
        r_date = JSON.parse(r_val)['timestamps']['release_date']
        release_id = JSON.parse(r_val)['release']['id']
        if r_date.nil?
          self.get_release_date_f_release(release_id) {|x| errata.push x}
          # self.get_release_date_f_html(errata[0]) {|x| errata.push x}
        else
          errata.push r_date.split('T')[0]
        end
      end
    end
    res
  end

  def self.run(release_name, pkg_name)
    self.release_date_of_each_advisory! self.parse_raw_html(self.query_for_raw_html(pkg_name), release_name)
  end
end


class PreJobs

  def self.get_competent_version
    config = self.load_config
    competent = config['competent_need_to_check']
    r_date = config['release_date']

    File.open('./manifest-rpm.txt').each_line do |line|
      competent.each do | item |
        if line =~ /#{item[0]}-[^a-zA-Z]/
          ver = line.split(' ')[0].sub("#{item[0]}-", '').sub('.x86_64', '')
          item << ver
        end
      end
    end

    [competent, r_date]
  end

  def self.load_config
    $log.info 'Loading config from ./config.yml'
    YAML.load File.open('./config.yml')
  end


  def self.mount_iso
    t_dir = Dir.mktmpdir

    $log.info "mounting #{iso_path} into #{t_dir}"
    `mount -o loop #{iso_path} #{t_dir}`

    $log.info "Copy 'manifest-rpm.txt' from #{t_dir}/isolinux/ to current dir"
    `cp #{t_dir}/isolinux/manifest-rpm.txt .`

    if File.exist? './manifest-rpm.txt'
      $log.info "umount #{t_dir}"
      `umount #{t_dir}`
    else
      $log.error 'Get mainfest-rpm.txt is failed'
      exit -1
    end
  end
end


class ParseData
  def self.run(fin_data)
    fin_data = fin_data
    tmp = ERB.new(DATA.read)
    self.send_res_mail tmp.result(binding)
  end

  def self.send_res_mail(m_body)
    message = <<MESSAGE_END
From: John Doe <jd@someplace.com>
To: rhevh-qe <rhevh-qe@redhat.com>
MIME-Version: 1.0
Content-type: text/html
Subject: #{iso_name} - Main package version check

#{m_body}
MESSAGE_END

    Net::SMTP.start('smtp.corp.redhat.com') do |smtp|
      smtp.send_message message, 'john-doe@someplace.com', 'rhevh-qe@redhat.com'
    end
  end
end
# ===================== main() =========================================================================================

if __FILE__ == $0

  # if Process.uid != 0
  #   $log.warn 'Must run scipt with `root` privilege'
  #   exit 0
  # end

  opts = GetoptLong.new(
      [ '--help', '-h', GetoptLong::NO_ARGUMENT],
      ['--release-date', '-r', GetoptLong::OPTIONAL_ARGUMENT]
  )

  release_date = nil

  opts.each do | opt, arg |
    case opt

      when '--help'
        puts <<-EOF
version_check.rb [OPTION] ... ISO_PATH

-h, --help:
   show help

--release-date [YYYY-MM-DD]:
   if release-date given here, then the one in config.yml will be over-written.

ISO_PATH: the absolute path of the iso

        EOF

      when '--release-date'
        if arg != ''
          if arg =~ /\d{4}-\d{2}-\d{2}/
            release_date = arg.to_s
          else
            $log.error 'Date should match format `YYYY-MM-DD`'
            exit 0
          end
        end
      else
        nil
    end
  end

  if ARGV.length != 1
    $log.warn 'Missing `ISO_PATH` argument (try --help)'
    exit 0
  end

  # raise "file #{ARGV[0]} does not exist" unless File.exist? ARGV[0]
  competent, release_date = PreJobs.get_competent_version
  $log.info "competent need to be checked are #{competent}"
  $log.info "release_date is #{release_date}"
  competent.each do |x|
    x.push(QueryErrata.run x[1], x[0])
  end

  $log.info 'Sending result to mail groups'
  ParseData.run competent
end

__END__
<html>
<head>
<style>
table, td, th {
  border-collapse: collapse;
  border: 1px solid black;
  padding: 5px;
}
.success {
  background-color: #dff0d8;
}
.active {
  background-color: #f5f5f5;
}
.cp_name {
  text-decoration: underline;
  color: RoyalBlue;
}
</style>
</head>
<body>


<% fin_data.each do |competent| %>
    <table class="table table-bordered">
      <tr class='active'>
        <th>Name</th>
        <th>Query For</th>
        <th>Version</th>
        <th>Release Date</th>
      </tr>
      <tr class='success'>
        <td><span class="cp_name"><%= competent[0].upcase %></span></td>

        <td><%= competent[1] %></td>

        <td><%= competent[2] %></td>

        <td>2014-06-12</td>
      </tr>
      <tr class='active'>
        <th colspan="4">Active Errata</th>
      </tr>
      <% competent[3][:active_errata].each do |errata| %>
        <% if errata[2].include? competent[2]
          @tr_class = 'success'
          else
          @tr_class = nil
          end
        %>

          <tr class="<%= @tr_class %>">
            <td><a href="https://errata.devel.redhat.com/advisory/<%= errata[0] %>"><%= errata[0] %></a></td>
            <td><%= errata[1] %></td>
            <td><%= errata[2] %></td>
            <td><%= errata[5].to_s %></td>
          </tr>

      <% end %>
      <tr class='active'>
        <th colspan="4">Shipped Errata</th>
      </tr>
      <% competent[3][:shipped_errata].each do |errata| %>
        <% if errata[3].include? competent[2]
          @tr_class = 'success'
          else
          @tr_class = nil
          end
        %>
          <tr class="<%= @tr_class %>">
            <td><a href="https://errata.devel.redhat.com/advisory/<%= errata[0] %>"><%= errata[0] %></a></td>
            <td><%= errata[1] %></td>
            <td><%= errata[3] %></td>
            <td><%= errata[5].to_s %></td>
          </tr>
      <% end %>
    </table>
    <br>
<% end %>

</body>
</html>