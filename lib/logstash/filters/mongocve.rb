# encodine: utf-8

require 'logstash/filters/base'
require 'logstash/namespace'
require 'logstash/environment'
require 'mongo'

class LogStash::Filters::MongoCVE < LogStash::Filters::Base

  config_name 'mongocve'

  # Config variables managed by Chef:
  config :mongodb_hostname, :validate => :string, :required => true
  config :mongodb_port, :validate => :string, :required => true
  config :db_name, :validate => :string, :required => true


  public
  # As the initialize method, start the MongoDB session --> "register" mandatory for a Logstash filter plugin
  def register
    @cpes_availables = Hash.new
    set_db_session
  end


  public
  # Open a new MongoDB session
  def set_db_session
    @connection_string = @mongodb_hostname + ':' + @mongodb_port
    begin
      @client = Mongo::Client.new([ @connection_string ], :database => @db_name )
      @db = @client.database
    rescue e
      puts '[open_db_session] Error conecting to ' + @db_name.to_s + ': ' + e.to_s
    end
  end


  public
  # Check if the DB session is opened, or open it if not
  def get_db_session
    return @client.get_session.session_id
  end


  public
  # Main search engine --> "filter" method mandatory for a Logstash filter plugin
  def filter(event)
    input_event = event.to_hash
    input_event.delete('@timestamp')
    input_event.delete('@version')
    puts '[filter] input_event: ' + input_event.to_s
    puts '[filter] input_event["cpe"]: ' + input_event["cpe"]
    cpe_p_v = get_prod_version(input_event["cpe"])
    # Check if the CPE was already found in a previous execution
    if !@cpes_availables.has_key?( input_event["cpe"] )
      puts '[filter] It\'s a new CPE.'
      # Create a new list entry to save the new CPE
      @cpes_availables[input_event["cpe"]] = []
      # Check DB session
      set_db_session
      cve_colls = get_collections
      db_response = []
      cve_colls.each do |coll|
        # Querying CPE coincidences into DB by every available collection
        db_response.concat( database(cpe_p_v[0], coll) )
      end
      without_versions = false
      without_versions = true if cpe_p_v[1].nil?
      cve_list = []
      db_response.each do |document|
        # Finding CPE coincidences for the given document
        cve_list += find_cpe(cpe_p_v, document, without_versions)
      end
      cve_list.each do |cve|
        # Enrich the input event with the CVE info and put into the output
        output_event = set_output_event(input_event, cve)
        yield output_event
        # Include the output into the saved CVE's events list for the given CPE
        puts '[filter] CVE info for the given CPE that will be saved: ' + cve.to_s
        @cpes_availables[input_event["cpe"]].push( cve )
      end
    else
      puts '[filter] CPE already saved: ' + @cpes_availables[input_event["cpe"]].to_s
      @cpes_availables[input_event["cpe"]].each do |saved_cve|
        # Generate an output event by every saved CVE for the given CPE
        output_event = set_output_event(input_event, saved_cve)
        yield output_event
      end
    end
    # To avoid to put the input event into the output
    event.cancel
  end


  # Generate the output event with the CVE info, without metadata
  def set_output_event(input_event, cve)
    out_event = LogStash::Event.new
    input_event.each { |k, v| out_event.set(k, v) }
    cve.each { |k, v| out_event.set(k, v) }
    out_event.remove('@timestamp')
    out_event.remove('@version')
    return out_event
  end


  # Get an array of two elements for a given CPE: vendor-product and version
  def get_prod_version(cpe_orig)
    #cpe_vendor_product_version = cpe_orig
    #cpe_vendor_product_version = cpe_orig.split('cpe:2.3:a:')[-1] if cpe_orig.match('cpe:2.3:a:')
    cpe_orig.match('cpe:2.3:a:') ? cpe_vendor_product_version = cpe_orig.split('cpe:2.3:a:')[-1] : cpe_vendor_product_version = cpe_orig
    cpe_result = []
    cpe_result.push( cpe_vendor_product_version.split(':')[0..1].join(':') )
    cpe_result.push( cpe_vendor_product_version.split(':')[2] ) if cpe_vendor_product_version.split(':').length >=3
    return cpe_result
  end


  # Convert the version into an array of its minimum subversions
  def version_converter(version)
    version_without_subreleases = version.to_s.split(/[^0-9\.]/)[0]
    if !version_without_subreleases.nil?
      return version_without_subreleases.split('.').map{|chr| chr.to_i}
    else
      return version_without_subreleases
    end
  end


  # Compare two ordered formatted versions
  #   # Returns -1 if v1 is lower than v2, 0 if equal or 1 if greater
  def compare_version(version1, version2)
    v1 = version_converter(version1)
    v2 = version_converter(version2)
    return v1 <=> v2
  end


  # Find a CPE coincidence into the given DB document (as a hash)
  def find_cpe(cpe, document, without_versions)
    cves = []
    cpe_nodes = document["configurations"]["nodes"]
    cpe_nodes.each do |cpe_nodes_elem|
      if cpe_nodes_elem.has_key?("cpe_match")
        cves.push( get_cve_data(document) ) if scroll_cpe_match(cpe, cpe_nodes_elem["cpe_match"], without_versions)
      end
      if cpe_nodes_elem.has_key?("children")
        cpe_nodes_elem["children"].each do |children_elem|
          cves.push( get_cve_data(document) ) if scroll_cpe_match(cpe, children_elem["cpe_match"], without_versions)
        end
      end
    end
    cves.each { |elem| (puts '[find_cpe] cves: ' + elem.to_s) }
    return cves.uniq
  end


  # Go down the list of available cpe23Uri elements into the cpe_match hash
  def scroll_cpe_match(cpe, cpe_match, without_versions)
    cpe_coincidence = false
    cpe_match.each do |cpe_match_elem|
      cpe_db = get_prod_version(cpe_match_elem["cpe23Uri"])
      if cpe[0] == cpe_db[0]
        unless without_versions
          if cpe_db[1] != '*' and !cpe_db[1].nil?
            cpe_coincidence = true if compare_version(cpe[1], cpe_db[1]) == 0
          elsif cpe_db[1] == '*'
            cpe_coincidence = true if version_range(cpe, cpe_match_elem)
          end
        else
          cpe_coincidence = true
        end
      end
    end
    return cpe_coincidence
  end


  # Check if the given version belongs to the versions range defined in CVE document
  def version_range(cpe, cpe_match_elem)
    inside_range = false
    if cpe_match_elem.has_key?("versionEndExcluding")
      if cpe_match_elem.has_key?("versionStartIncluding")
        inside_range = true if compare_version(cpe[1], cpe_match_elem["versionStartIncluding"]) != -1 and compare_version(cpe[1], cpe_match_elem["versionEndExcluding"]) == -1
      elsif cpe_match_elem.has_key?("versionStartExcluding")
        inside_range = true if compare_version(cpe[1], cpe_match_elem["versionStartExcluding"]) == 1 and compare_version(cpe[1], cpe_match_elem["versionEndExcluding"]) == -1
      else
        inside_range = true if compare_version(cpe[1], cpe_match_elem["versionEndExcluding"]) == -1
      end
    end
    if cpe_match_elem.has_key?("versionEndIncluding")
      if cpe_match_elem.has_key?("versionStartIncluding")
        inside_range = true if compare_version(cpe[1], cpe_match_elem["versionStartIncluding"]) != -1 and compare_version(cpe[1], cpe_match_elem["versionEndIncluding"]) != 1
      elsif cpe_match_elem.has_key?("versionStartExcluding")
        inside_range = true if compare_version(cpe[1], cpe_match_elem["versionStartExcluding"]) == 1 and compare_version(cpe[1], cpe_match_elem["versionEndIncluding"]) != 1
      else
        inside_range = true if compare_version(cpe[1], cpe_match_elem["versionEndIncluding"]) != 1
      end
    end
    if cpe_match_elem.has_key?("versionStartExcluding") and !cpe_match_elem.has_key?("versionEndExcluding") and !cpe_match_elem.has_key?("versionEndIncluding")
      inside_range = true if compare_version(cpe[1], cpe_match_elem["versionStartExcluding"]) == -1
    elsif cpe_match_elem.has_key?("versionStartIncluding") and !cpe_match_elem.has_key?("versionEndExcluding") and !cpe_match_elem.has_key?("versionEndIncluding")
      inside_range = true if compare_version(cpe[1], cpe_match_elem["versionStartIncluding"]) != -1
    end
    inside_range = true if !cpe_match_elem.has_key?("versionStartExcluding") and !cpe_match_elem.has_key?("versionStartIncluding") and !cpe_match_elem.has_key?("versionEndExcluding") and !cpe_match_elem.has_key?("versionEndIncluding")
    return inside_range
  end


  # Get the extra CVE info (CVSS data and URL)
  def get_cve_data(document)
    cve_extra = Hash.new
    cve_extra["cve"] = document["cve"]["CVE_data_meta"]["ID"]
    if document["impact"].has_key?("baseMetricV3")
      cve_extra["score"] = document["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
      cve_extra["metric"] ="cvssV3"
      cve_extra["severity"] = document["impact"]["baseMetricV3"]["cvssV3"]["baseSeverity"]
    else
      cve_extra["score"] = document["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
      cve_extra["metric"] = "cvssV2"
      cve_extra["severity"] = document["impact"]["baseMetricV2"]["severity"]
    end
    cve_extra["cve_info"] = 'https://nvd.nist.gov/vuln/detail/' + cve_extra["cve"].to_s
    return cve_extra
  end

  # Get the list of DB collections
  def get_collections
    response = @db.collection_names
    return response.to_a.sort
  end


  # CVE's by CPE query
  def database(cpe_vendor_product, collection)
    query_one_list = { :'configurations.nodes.cpe_match.cpe23Uri' => /:a:#{cpe_vendor_product}:/ }
    query_several_lists = { :'configurations.nodes.children.cpe_match.cpe23Uri' => /:a:#{cpe_vendor_product}:/ }
    response = @db["#{collection}"].find( { :$or => [ query_one_list , query_several_lists ] } ).to_a
    puts '[database] response lenght: ' + response.length().to_s
    return response
  end


  # Tool to count all the CVE's available in DB
  def count_regs
    cve_colls = get_collections
    num = 0
    cve_colls.each do |coll|
      count = @db["#{coll}"].count().to_i
      puts coll + ' - ' + count.to_s
      num += count
    end
    puts '[count_regs] Total documents: ' + num.to_s
  end


end
