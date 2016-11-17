# file for scraping the cves and updated version from apple page
import re
import urllib2
from bs4 import BeautifulSoup
from time import strptime


advisory_url = "https://support.apple.com/en-in/HT207274"

latest_iTunescheck_name = "2894295-Apple_iTunes_Security_Update_12.5.1_for_Windows_copy.xml"

svnid_file = "SAURABH_ids_copy.txt"

open_webpage = urllib2.urlopen(advisory_url).read()
soup = BeautifulSoup(open_webpage,"lxml")

#extract the set of CVEs
cve_set = set()
for string in soup.stripped_strings:
    if string.__contains__("CVE-") and bool(re.search(r'\d',string)):
        cve_number = re.search(r'CVE[-\d]+',string).group(0)
        if cve_number is not None:
            cve_set.add(cve_number)

#search for iTunes version
for string in soup.stripped_strings:
    updated_version = re.search(re.compile('.*iTunes\s(\d+(?:\.\d+)+).*'), string)
    if updated_version is not None:
        updated_version = updated_version.group(1)
        break

#search for Release Date
for string in soup.stripped_strings:
    date_string = re.search(re.compile('.*Released\s(.+)'), string)
    if date_string is not None:
        date_with_comma = date_string.group(1)
        date = date_with_comma.replace(",","").strip()
        date_list = date.split()
        month_name = date_list[0][0:3]
        month_num = strptime(month_name,"%b").tm_mon
        release_date = "-".join(map(str,[date_list[2],month_num,date_list[1]]))
        break

#print "The CVEs covered are :", cve_set
#print "The updated version is :", product_version
#print "The release date is :", release_date

#get the svn ids to work with
id_count = 3
svn_ids = list()
with open(svnid_file,"r+") as id_file:
    id_file.seek(0)
    while id_count != 0:
        line_read = id_file.readline().strip()
        if bool(re.search(r'\d',line_read)):
            id = re.search(re.compile(r'.*:(\d+).*'),line_read)
            svn_ids.append(id.group(1))
            id_count = id_count - 1


#modify the latest check
with open(latest_iTunescheck_name,'r+') as latest_iTunescheck :

    soup = BeautifulSoup(latest_iTunescheck,"html.parser")
    #print soup.prettify()

    #delete all reference tags and add new cve references
    for reference_tag in soup.findAll("reference"):
        reference_tag.decompose()

    add_tag_below = soup.affected
    for cves in cve_set:
        reference_tag = soup.new_tag("reference", ref_id=cves, ref_url=advisory_url)
        add_tag_below.insert_after(reference_tag)


    #add new published date
    soup.vendor_data['published_on'] = release_date


    #replace def id, tst id and version
    old_def_id = re.search(re.compile(r'.*:(\d+).*'),soup.definition['id']).group(1)
    old_test_id = re.search(re.compile(r'.*:(\d+).*'),soup.file_test['id']).group(1)
    old_state_id = re.search(re.compile(r'.*:(\d+).*'),soup.file_test.state['state_ref']).group(1)

    title_string = soup.title.string
    old_version = re.search(re.compile(".*\s(\d+(?:\.\d+)+)\s.*"),title_string).group(1)

    old_ids = [old_def_id,old_test_id,old_state_id]
    soup_string = str(soup)
    soup_string = soup_string.replace(old_version,updated_version)
    for old_id, new_id in zip(old_ids, svn_ids):
        soup_string = soup_string.replace(old_id,new_id)

    new_soup = BeautifulSoup(soup_string,'html.parser')
    print new_soup.prettify()
    new_check_name = str(svn_ids[0]) + "-Apple_iTunes_Security_Update_" + str(updated_version) + "_for_Windows_copy.xml"
    with open(new_check_name,"w") as new_iTunescheck:
        new_iTunescheck.write(new_soup.prettify('utf-8'))

