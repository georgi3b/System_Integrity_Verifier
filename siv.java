import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Scanner;
import java.util.Set;

public class siv {

	public static void main(String[] args) {
		siv s = new siv();
		// parsing the command line arguments
		
		s.parseArguments(args);
		// starting the program in initialisation or verification mode
		if (!s.verification_mode) {
			//if (!args[0].equals("-h"))
			System.out.println("Starting initialisation mode...");
			s.initialisationMode();
		} else {			
			
			System.out.println("Starting verification mode...");
			s.verificationMode();
				
		}

	}

	private Path directory_path;
	private Path verificationFile_path;
	private Path reportFile_path;
	private String hashFunction;
	private Scanner scanner;
	private boolean verification_mode;
	private boolean checkD = false, checkV = false, checkR = false, checkH = false;

	public siv() {
		this.scanner = new Scanner(System.in);
	}

	/*
	 * This function reads the command line arguments, and sets the mode to initialisation or verification.
	 * I reads the paths to the monitored directory,and to the verification and report files. It also 
	 * performs the corresponding checks. It initialises the hash function used as a message digest.
	 */
	private boolean parseArguments(String[] args) {
		boolean done = false;
		try {
			if (args[0].equals("-i")) {
				// initialization mode
				verification_mode = false;
				parsePaths(args, 1);
				parsePaths(args, 3);
				parsePaths(args, 5);
				parsePaths(args, 7);
				//Check if the verification file exists
				if (Files.exists(verificationFile_path)) {
					askIfOverwrite("verification");
				}
				//Check if the report file exists
				if (Files.exists(reportFile_path)) {
					askIfOverwrite("report");
				}
				scanner.close();
			} else if (args[0].equals("-v")) {
				// verification mode
				verification_mode = true;
				parsePaths(args, 1);
				parsePaths(args, 3);
				parsePaths(args, 5);
				//don't care about the -H option
				//check if the report file exists
				if (Files.exists(reportFile_path)) {
					askIfOverwrite("report");
				}
				//check if the verification file exists
				if (!Files.exists(verificationFile_path)) {
					System.err.println("Invalid verification file. User -h for help.");
					System.exit(0);
				}
				scanner.close();
			} else if (args[0].equals("-h")) {
				this.help();
				System.exit(0);
			} else {
				System.err.println("ERROR:invalid initial parameters. Use -h for help.");
			}
		} catch (IndexOutOfBoundsException ex) {  //catches any error in the number of parameters
			System.err.println("Please specify all the required parameters.\n" + "Use -h for help.");
			System.exit(0);
		}

		return done;

	}

	private boolean parsePaths(String[] args, int i) {
		Path path=null;
	
		if (args[i+1] != null)
			path = Paths.get(args[i + 1]);
	
		if (!args[0].equals("-h")) {
			if (args[i].equals("-D")) {
				//if the directory wasn't already specified get the path to the directory
				if (!checkD) {
					if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
						directory_path = path;
						// System.out.println("Monitored directory:" + directory_path);
						checkD = true;
					} else {
						System.err.println(
								"INVALID DIRECTORY. Please specify an existing directory to monitor.Use -h for help.");
						System.exit(0);
					}
				} else {
					System.err.println("ERROR:argument -D already specified. Please try again.");
					System.exit(0);
				}
			} else

			if (args[i].equals("-V")) {
				//if the verification file wasn't already specified, get its path
				if (!checkV) {
					try {
						if (!path.startsWith(directory_path)) { 
							// verification file is outside monitored directory
							verificationFile_path = Paths.get(path.toString() + ".csv");
							// System.out.println("Verification file:" + verificationFile_path);
							checkV = true;
						} else {
							System.err.println(
									"INVALID FILE PATH. Please specify another directory as location for the verification file.Use -h for help.");
							System.exit(0);
						}
					} catch (NullPointerException ex) {
						System.err.println("ERROR: Please specify directory to monitor first. Use -h for help.");
						System.exit(0);
					}
				} else {
					System.err.println("ERROR:argument -V already specified. Please try again.");
					System.exit(0);
				}
			} else if (args[i].equals("-R")) {
				//if the report file wasn't already specified, get its path
				if (!checkR) {
					try {
						if (!path.startsWith(directory_path)) { // verification file is outside monitored directory
							reportFile_path = Paths.get(path.toString());
							// System.out.println("Report file:" + reportFile_path);
						} else {
							System.err.println(
									"INVALID FILE PATH. Please specify another directory as location the report file.Use -h for help.");
							System.exit(0);
						}
					} catch (NullPointerException ex) {
						System.err.println("ERROR: Please specify directory to monitor first. Use -h for help.");
						System.exit(0);
					}
				} else {
					System.err.println("ERROR:argument -R already specified. Please try again.");
					System.exit(0);
				}

			} else if (args[i].equals("-H")) {
				if (verification_mode) {
					System.err.println("ERROR: Verification mode doesn't accept -H as input. Use -h for help.");
					System.exit(0);
				}
				//if the hash function wasn't already specified
				if (!checkH) {
					String hashF = args[i + 1];
					if (hashF.equalsIgnoreCase("MD5")) {
						hashFunction = hashF.toUpperCase();
					} else if (hashF.equalsIgnoreCase("SHA1") || hashF.equalsIgnoreCase("SHA256")
							|| hashF.equalsIgnoreCase("SHA384") || hashF.equalsIgnoreCase("SHA512")) {
						hashFunction = "SHA-" + hashF.substring(3);
					} else {
						System.err.println(
								hashF + " is not supported. Please choose between SHA1,MD5,SHA256,SHA384 or SHA512.");
						System.exit(0);
					}
				} else {
					System.err.println("ERROR:argument -H already specified. Please try again.");
					System.exit(0);
				}

			} else {
				System.err.println("ERROR:invalid parameters.Use -h for help.");
				System.exit(0);
			}
		}
		return true;
	}

	/*
	 * This is the initialisation mode. The SIV starts traversing the directory contents
	 * of the monitored directory and for every file/directory in it it prints the given data 
	 * (file name, size, owner, group owner, permissions, last modification date) 
	 * into the verification file, which is a CSV file. 
	 * While recursively traversing the directories it also counts them and the files.
	 * In the end this data and the time needed to finish the initialisation are
	 * written to the report file.
	 */
	private void initialisationMode() {
		long start = System.currentTimeMillis();
		PrintWriter verificationFileWr = null;
		int[] numbers = null;   //array of integers to store number of directories and files parsed
		try {
			BufferedWriter bwriter = new BufferedWriter(new FileWriter(verificationFile_path.toString(), false));
			verificationFileWr = new PrintWriter(bwriter);
			verificationFileWr.println("FILE;;SIZE;;OWNER;;GROUP;;PERMISSIONS;;LAST_MODIFICATION_DATE;;" + hashFunction);
			numbers = new int[2];
			this.traverseDirectories(directory_path, verificationFileWr, numbers);
			//System.out.println("No. directories: " + numbers[0]);
			//System.out.println("No. files: " + numbers[1]);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} finally {
			verificationFileWr.close();
		}
		long end = System.currentTimeMillis();
		double time = (double) (end - start) / 1000;
		System.out.println("Time needed to complete initialization mode:" + time+" seconds." );
		//verificationFileWr.close();
		this.writeReportFile(numbers, time);
	}
	
	/*
	 * The method that traverses the directories in initialisation mode. For every directory/file 
	 * found it gets its details and saves them into the verification file.  
	 */
	private void traverseDirectories(Path path, PrintWriter writer, int[] numbers) throws IOException {
		String details = "";
		long size;
		if (!Files.isDirectory(path)) {
			size  = Files.size(path);
		}else {
			size = 0;
		}
		PosixFileAttributes attributes = Files.getFileAttributeView(path,PosixFileAttributeView.class).readAttributes();
		UserPrincipal owner = attributes.owner();
		GroupPrincipal group = attributes.group();
		Set<PosixFilePermission> permissions = attributes.permissions();
		// permissions: 4 if readable, 2 if writable, 1 if executable
		String permissionsOct = this.getOctalPermissions(permissions);
		FileTime lastModified = Files.getLastModifiedTime(path);
		String hash;
		if (!Files.isDirectory(path)) {
			hash = this.getHashedContents(path);
		} else {
			hash = "dir";
		}
		details += path + ";;" + size + ";;" + owner + ";;" + group + ";;" + permissionsOct + ";;"
				+ lastModified + ";;";
		details += hash;
		writer.println(details);
		
		if (!Files.isDirectory(path)) {
			// BASE CASE			
			// increase number of parsed files
			numbers[1]++;
		} else {
			// RECURSION
			// increase number of parsed directories
			numbers[0]++;
			try {
				DirectoryStream<Path> stream = Files.newDirectoryStream(path);
				for (Path entry : stream) {
					traverseDirectories(entry, writer, numbers);
				}
				stream.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

	}

	/*
	 * Method that performs the verification. It reads the verification file, saves its
	 * conents into a hashmap (lookup time = n) and then verifies the directory tree to 
	 * check for modified files.
	 * While parsing the files it checks already if the file is still there. If
	 * the file was deleted it prints to the report file the warning. 
	 */
	private void verificationMode() {
		long start = System.currentTimeMillis();
		BufferedReader reader = null;
		PrintWriter reportFileWriter = null;
		HashMap<Path, String> files = new HashMap<>();
		int[] numbers = new int[3];
		try {
			reader = new BufferedReader(new FileReader(verificationFile_path.toString()));
			reportFileWriter = new PrintWriter(new BufferedWriter(new FileWriter(reportFile_path.toString())));
			// read the hashing function from the first line of file
			String firstLine = reader.readLine();
			String sep = ";;";
			try {
				hashFunction = this.getFileHashFunction(firstLine);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				System.err.println(e);
			}
			String line;
			while ((line = reader.readLine()) != null) {
				String[] tokens = line.split(sep);
				Path path = Paths.get(tokens[0]);
				// while parsing the verification file, I check that the given file/directory still
				// exists. If no, print warning, otherwise add it to the hashmap.
				if (!Files.exists(path)) {
					if (tokens[6].equals("dir")) {
						reportFileWriter.println("WARNING: Directory " + path + " was removed or moved from its previous location.");
					}else {
						reportFileWriter.println("WARNING: File " + path + " was removed or moved from its previous location.");
					}
					numbers[2]++;
				} else {
					files.put(path, sep + tokens[1] + sep + tokens[2] + sep + tokens[3] + sep + tokens[4] + sep + tokens[5]
						+ sep + tokens[6]);
				}
			}
			// recursively iterate through directory contents
			//System.out.println("Size of hashmap before verification: " + files.size());
			
			//recursively iterate through the directories
			this.verifyDirectories(directory_path, files, reportFileWriter, numbers);
			
			//System.out.println("Size of hashmap after verification: " + files.size());


		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			reader.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		reportFileWriter.close();
		
		long end = System.currentTimeMillis();
		double time = (double) (end - start) / 1000;
		System.out.println("Time needed to complete verification mode:" + time +" seconds.");
		
		// appending the report of the verification mode to the warnings
		this.writeReportFile(numbers, time);
	}

	/*
	 * Recursive functions which iterates through the directory tree and verifies the 
	 * information of the found files against the one contained in the verification file.
	 */
	private void verifyDirectories(Path path, HashMap<Path, String> files, PrintWriter writer, int[] numbers)
			throws IOException {
		
		boolean toDelete = false;
		if(files.containsKey(path)){
			toDelete=true;
			boolean dir=false;
			if (Files.isDirectory(path)){
				dir = true;
			}
			this.compareInfo(path, files, writer, numbers, dir);
		} else {
			//File or directory is new, therefore not in the verification file
			if (Files.isDirectory(path)) {
				writer.println("WARNING: Directory " + path + " has been added.");
			} else {
				writer.println("WARNING: File " + path + " has been added.");
			}
			numbers[2]++;
		}
		if (toDelete) {
			files.remove(path);
		}
		
		if (!Files.isDirectory(path)) {
			//BASE CASE
			numbers[1]++;
		} else {
			// RECURSION
			// increase number of parsed directories
			numbers[0]++;
			try {
				DirectoryStream<Path> stream = Files.newDirectoryStream(path);
				for (Path entry : stream) {
					verifyDirectories(entry,files, writer, numbers);
				}
				stream.close();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}
	}

	/*
	 * The method that compares the data and information of the file/directory as given in the current directory tree
	 * with the data stored in the verification file.
	 */
	private void compareInfo(Path path, HashMap<Path, String> files, PrintWriter writer, int[] numbers, boolean dir)
			throws IOException { 
		String[] properties = null;
		properties = files.get(path).split(";;");
		PosixFileAttributes attributes = Files.getFileAttributeView(path,PosixFileAttributeView.class).readAttributes();
		UserPrincipal owner = attributes.owner(); 
		GroupPrincipal group = attributes.group();

		// Computed file properties vs stored file properties
		if (!dir) {
			if (Files.size(path) != Long.parseLong(properties[1])) {
				writer.println("WARNING: File " + path + " size has changed.");
				numbers[2]++;
			}
		}
		if (!attributes.owner().toString().equals(properties[2])) {
			if (dir) {
				writer.println("WARNING: Directory "+ path +" owner has changed.");
			} else {
				writer.println(" WARNING: File " + path +" owner has changed.");
			}
			numbers[2]++;
		}
		if (!attributes.group().toString().equals(properties[3])) {
			if (dir) {
				writer.println("WARNING: Directory " + path + " group has changed.");
			}else {
				writer.println("WARNING: File " + path + " group has changed.");
			}
			numbers[2]++;
		}
		String permissionsOct = this.getOctalPermissions(attributes.permissions());
		if (!permissionsOct.equals(properties[4])) {
			if(dir) {
				writer.println("WARNING: Directory " + path + " access rights have changed.");
			}else {
				writer.println("WARNING: File " + path + " access rights have changed.");
			}
			numbers[2]++;
		}
		if (!Files.getLastModifiedTime(path).toString().equals(properties[5])) {
			if (dir) {
				writer.println("WARNING: " + path + " Last modification time of directory has changed.");
			}else {
				writer.println("WARNING: " + path + " Last modification time of file has changed.");
			}
			numbers[2]++;
		}
		if (!dir) {
			if (!this.getHashedContents(path).equals(properties[6])) {
				writer.println("WARNING: " + path + "File contents have changed.");
				numbers[2]++;
			}
		}

	}

	/*
	 * help mode: read information from the help file and print it out.
	 */
	private void help() {
		System.out.println("This is the help mode.");
		BufferedReader reader = null;
		try {
			reader = new BufferedReader(new FileReader("help.txt"));
			String line;
			while ((line = reader.readLine())!=null) {
				System.out.println(line);
			}
			reader.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void writeReportFile(int[] numbers, double time) {
		PrintWriter reportFileWriter = null;
		try {
			//create a writer. Append this information to the file only in verificatio mode,
			//otherwise rewrite it.
			BufferedWriter bwriter = new BufferedWriter(new FileWriter(reportFile_path.toString(), verification_mode));
			reportFileWriter = new PrintWriter(bwriter);
			reportFileWriter.println("Monitored directory: " + directory_path);
			reportFileWriter.println("Verification file: " + verificationFile_path);
			reportFileWriter.println("Report file: " + reportFile_path);
			reportFileWriter.println("Number of directories parsed: " + numbers[0]);
			reportFileWriter.println("Number of files parsed: " + numbers[1]);
			if (verification_mode) {
				reportFileWriter.println("Number of warnings issued: " + numbers[2]);
				reportFileWriter.println("Time to complete verification mode: " + time + " seconds.");
			} else {
				reportFileWriter.println("Time to complete initialization mode: " + time + " seconds.");
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			reportFileWriter.close();
		}

	}
	
	/*
	 * help function which converts the Posix permissions into octal.
	 */
	private String getOctalPermissions(Set<PosixFilePermission> perm) {
		// permissions: 4 if readable, 2 if writable, 1 if executable
		int pOwn = 0, pGr = 0, pOth = 0;
		for (PosixFilePermission right : perm) {
			switch (right.toString()) {
			case "OWNER_READ":
				pOwn += 4;
				break;
			case "OWNER_WRITE":
				pOwn += 2;
				break;
			case "OWNER_EXECUTE":
				pOwn += 1;
				break;
			case "GROUP_READ":
				pGr += 4;
				break;
			case "GROUP_WRITE":
				pGr += 2;
				break;
			case "GROUP_EXECUTE":
				pGr += 1;
				break;
			case "OTHERS_READ":
				pOth += 4;
				break;
			case "OTHERS_WRITE":
				pOth += 2;
				break;
			case "OTHERS_EXECUTE":
				pOth += 1;
				break;
			default:
				break;

			}
		}
		String permissionsOct = pOwn + "" + pGr + "" + pOth;
		return permissionsOct;
	}

	/*
	 * help function that parses the first line of the verification file to 
	 *get which hash function was used.
	 */
	private String getFileHashFunction(String line) throws Exception {
		String sep = ";;";
		if (line != null && !line.equals("")) {
			String[] tokens = line.split(sep);
			String hashF = tokens[6];
			if (hashF.equalsIgnoreCase("MD5") || hashF.equalsIgnoreCase("SHA-1") || hashF.equalsIgnoreCase("SHA-256")
					|| hashF.equalsIgnoreCase("SHA-358") || hashF.equalsIgnoreCase("SHA-512")) {
				return hashF;
			}
		}
		throw new Exception("Hash function can't be recovered.");
	}
 
	/*
	 * help function which hashes the file.
	 */
	private String getHashedContents(Path path) throws IOException {
		byte[] hash = null;
		String result = null;
		if (Files.isReadable(path)) {
			FileInputStream input = null;
			try {
				input = new FileInputStream(new File(path.toString()));
			} catch (FileNotFoundException e2) {
				System.err.println("An unexpected error has occurred.");
				System.exit(0);
			}
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance(hashFunction);
			} catch (NoSuchAlgorithmException e1) {
				// TODO Auto-generated catch block
				System.err.println("ERROR: Hashing algorithm not supported. Use -h for help.");
				System.exit(0);
			}
			md.reset();
			byte[] bytes = new byte[1024];
			int numBytes = 0;
			while ((numBytes = input.read(bytes)) != -1) {
				md.update(bytes, 0, numBytes);
			}
			input.close();
			hash = md.digest();
			// convert the byte array to HEXString format
			StringBuffer hexString = new StringBuffer();
			for (int i = 0; i < hash.length; i++) {
				hexString.append(Integer.toHexString(0xFF & hash[i]));
			}
			result = hexString.toString();
		} else {
			System.err.println("ERROR:Java doesn't have the permission to read the file " + path);
		}
		return result;
	}

	/*
	 * help function which makes sure the user wants to overwrite the given files
	 */
	private void askIfOverwrite(String file) {
		System.out.println("The " + file + " file exists already. Do you want to overwrite it? Yes/No:");
		String input = scanner.nextLine();
		while (true) {
			if (input.equalsIgnoreCase("no") || input.equalsIgnoreCase("n")) {
				System.exit(0);
			}
			if (input.equalsIgnoreCase("Yes") || input.equalsIgnoreCase("y")) {
				break;
			}
			System.out.println("Please write yes/no:");
			input = scanner.nextLine();
		}
		System.out.println("The file will be overwritten.");

	}

}
