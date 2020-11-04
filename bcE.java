/*
 * Bryce Jensen
 * 10/16/2020
 *
 *  openjdk 11.0.1 2018-10-16 LTS
 *  to compile:
 *      $ javac bcE.java
 *
 *  to run, in one shell:
 *     $ java bcE
 *
 *  Files needed to run:
 *                     a. checklist-block.html
 *                     b. Blockchain.java
 *                     c. BlockchainLog.txt
 *                     d. BlockchainLedgerSample.json
 *                     e. BlockInput0.txt
 *                     f. BlockInput1.txt
 *                     g. BlockInput2.txt
 *
 * Thanks: http://www.javacodex.com/Concurrency/PriorityBlockingQueue-Example
 *
 *
 * Notes:
 *       This is mini-project E of the Blockchain assignment.
 *
 *       It contains a simple blockchain program with five nodes. A dummy genesis block and
 *       four other simple blocks.
 *
 *       Each block contains some arbitrary data, the hash of the previous block,
 *       a timestamp of its creation, and the hash of the block itself.
 *
 *       When calculating the hash for each block, the contained elements in the block
 *       are turned into strings and concatenated together with a nonce to then be hashed.
 *
 *       The verifying of blocks is done by taking in the block hash prefix and trying every possible
 *       combination by incrementing our nonce  until our prefixString is equal to our designated prefix
 *		
 *	    It currently can marshall its data out into JSON format and compile successfully.
 *
 *      As of 10/17/2020 at 10:41am, I" have my readFromJSON() method flushed out. Will need to clone
 *      and test in the VM to make sure everything still compiles and does what I expect it to.
 *
 *	Starting implementation of my program accepting command line arguments
 * 	today on 10/22/2020.
 */

import java.io.*;
import java.lang.reflect.Type;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;


class BlockRecord implements Serializable
// block record class made serializable in order to send via socket. Will hold block data as we dynamically build our blockchain
{
    protected String BlockID;
    // will hold the blocks ID
    protected String SignedBlockID;
    // string to hgold our verified Block ID
    protected String VerificationProcessID;
    // holds the ID of the process that verifies the block, or tries to
    protected String CreatingProcessID;
    // holds a string version of the creating process id
    protected int BlockNum = 0;
    // member var to hold the blocks number
    protected String TimeStamp;
    // the blocks time stamp
    protected String TimestampAdded;
    // timestamp string of when a block was added
    protected String TimestampVerified;
    // timestamp string pf when a block is verified
    protected String PreviousHash;
    // hash of the previous block
    protected UUID uuid;
    // how we will marshall data to JSON
    protected String Data;
    // the data contained in the block
    protected String RandomSeed;
    // this will be our means of trying to verify the block
    protected String WinningHash;
    // the hash of our winning guess
    protected String SHA256String;
    // string to hold our unverified SHA256 hash
    protected String SignedSHA256;
    // string to hold the verified SHA256 string
    protected String FirstName = "";
    //
    protected String LastName = "";

    protected String SSN = "";

    protected String DOB = "";

    protected String Diagnosis = "";

    protected String Treatment = "";

    protected String RX = "";



    public String getFirstName() {
        return this.FirstName;
    }
    public void setFirstName(String _fName) {
        this.FirstName = _fName;
    }

    public String getLastName()
    {
        return this.LastName;
    }
    public void setLastName(String _lName) {
        this.LastName = _lName;
    }

    public String getDOB() { return this.DOB; }
    public void setDOB(String _dob) {
        this.DOB = _dob;
    }

    public String getSSN() { return this.SSN; }
    public void setSSN(String _ssn) {
        this.SSN = _ssn;
    }

    public String getRX() { return this.RX; }
    public void setRX(String _rx) {
        this.RX = _rx;
    }

    public String getDiag() { return this.Diagnosis; }
    public void setDiag(String _diag) {
        this.Diagnosis = _diag;
    }

    public String getTreat() { return this.Treatment; }
    public void setTreat(String _treat) {
        this.Treatment = _treat;
    }


    public String getTimeStamp() { return TimeStamp; }
    public void setTimeStamp(String _timeStamp) { this.TimeStamp = _timeStamp; }

    public String getTimeStampVerified() { return TimestampVerified; }

    public String getTimestampAdded() { return TimestampAdded; }


    public int getBlockNum() { return BlockNum; }
    public void setBlockNum(int _blockNum) { BlockNum = _blockNum; }

    public String getHashedBlock() { return SHA256String; }
    public void setHashedBlock(String _sha256string) { SHA256String = _sha256string; }

    public String getSignedSHA256() { return SignedSHA256; }
    public void setSignedSHA256(String _sha256string) { this.SignedSHA256 = _sha256string; }

    public String getCreatingProcessID() { return CreatingProcessID; }
    public void setCreatingProcessID(String _creatingProcess) { this.CreatingProcessID = _creatingProcess; }

    public String getBlockID() { return this.BlockID; }
    public void setBlockID(String _BlockID) { this.BlockID = _BlockID; }

    public String getSignedBlockID() { return this.SignedBlockID; }
    public void setSignedBlockID(String signedBlockID) { SignedBlockID = signedBlockID; }

    public String getVerificationProcessID() { return VerificationProcessID; }
    public void setVerificationProcessID(String _VerificationProcessID) { this.VerificationProcessID = _VerificationProcessID; }

    public String getPreviousHash() { return this.PreviousHash; }
    public void setPreviousHash(String _PreviousHash)
    {
        this.PreviousHash = _PreviousHash;
    }
    // getter/setter for previousHash

    public UUID getUUID()
    {
        return this.uuid;
    }
    public void setUUID(UUID _uuid)
    {
        this.uuid = _uuid;
    }
    // get/setter for unique identifier

    public String getRandomSeed()
    {
        return this.RandomSeed;
    }
    public void setRandomSeed(String _RandomSeed)
    {
        this.RandomSeed = _RandomSeed;
    }
    // getter / setters fro gettting and setting the random seed

    public String getWinningHash()
    {
        return this.WinningHash;
    }
    public void setWinningHash(String _WinningHash)
    {
        this.WinningHash = _WinningHash;
    }
    // getter and setters to obtain or set the winning hash

    public int compareTo(BlockRecord _otherBlock) { return this.TimestampAdded.compareTo(_otherBlock.TimestampAdded); }
    public int compare(BlockRecord _o1, BlockRecord _o2)
    {
        return _o1.BlockNum - _o2.BlockNum;
    }
}

class Ports
{
    protected static final int KeyManagementPort =6000;
    // declare a final int representing our key management port number
    protected static int KeyServerPortBase = 6250;
    // starting port num when the process first runs for the Key Server
    protected static int UVBServerPortBase = 6450;
    // starting point num when the process fisrt runs for the Unverified Block Server
    protected static int BlockchainServerPortBase = 6650;
    // starting port num when the process first runs for Blockchain Server

    public static int KeyServerPort;
    // where we will hold the incremented port num for new processes running Key Server
    public static int UVBServerPort;
    // where we will hold the incremented port num for new processes running Unverified Blockchain Server
    public static int BlockchainServerPort;
    // where we will hold the incremented port num for new processes running Blockchain Server

    public static int[] KeyServerPortsArray = new int[bcE.ProcessCount];
    // an integer array to store all the key server ports
    public static int[] UVBServerPortsArray = new int[bcE.ProcessCount];
    // an integer array to store all the key server ports
    public static int[] BlockchainServerPortsArray = new int[bcE.ProcessCount];

    public static void setPorts()
    {
        KeyServerPort = KeyServerPortBase + (bcE.ProcessID * 1000);
        // assign Key Server port to every new process incremented by 1000
        UVBServerPort = UVBServerPortBase + (bcE.ProcessID * 1000);
        // assign Unverified Blockchain Server port to every new process incremented by 1000
        BlockchainServerPort = BlockchainServerPortBase + (bcE.ProcessID * 1000);
        // assign Blockchain Server port to every new process incremented by 1000
    }

    public static void setPorts(int _runningProcesses)
    {
        for (int i = 0; i <  _runningProcesses; i++) {
            KeyServerPortsArray[i]  = KeyServerPortBase + i;
            // set the port numbers for all processes accessing Key Server
            UVBServerPortsArray[i] = UVBServerPortBase + i;
            // set the port numbers for all processes accessing Unverified Block Server
            BlockchainServerPortsArray[i] = BlockchainServerPortBase + i;
            // set the port numbers for all processes accessing Blockchain Server
        }
    }


    public static int getKeyServerPort() { return KeyServerPort; }

    public static int getUVBServerPort() { return UVBServerPort; }

    public static int getBlockchainServerPort() { return BlockchainServerPort; }

    public static int[] getKeyServerPortsArray() { return KeyServerPortsArray; }
    // getter to obtain the Key Server Ports Array with all Key Server Ports
    public static int[] getUVBServerPortsArray() { return UVBServerPortsArray; }
    // getter to obtain the UVB server Ports Array with all UVB Server Ports
    public static int[] getBlockchainServerPortsArray() { return BlockchainServerPortsArray; }
    // getter to obtain the Blockchain server Ports Array with all Blockchain Server Ports
}

class KeyManager // class to manage the creation and distribution of public and private keys
{
    KeyPair key_pair = null;
    // declare and initialize new keypair var to null
    PublicKey public_key = null;
    // declare and initialize new public key variable to null
    PrivateKey private_key = null;
    // declare and initialize new private key to null
    Signature signature = null;
    // declare and initialize a new Signature var signer to null

    public KeyManager(PublicKey _publicKey) throws Exception { String signAlg = "SHA1withRSA"; this.signature = Signature.getInstance(signAlg); this.public_key = _publicKey; }
    // constructor that accepts and binds new public key
    public KeyManager() throws Exception { String signAlg = "SHA1withRSA"; this.signature = Signature.getInstance(signAlg); }
    // second constructor that just return the signing encryption algorithm

    public void generateKeyPair(long _seed) throws Exception {
        String encryption_algorithm = "RSA";
        // declare a string containing rsa alg for encryption
        String hashing_algorithm = "SHA1PRNG";
        // declare string for sha1prng alg for hashing
        String hash_algorithm_provider = "SUN";
        // declare string for hash algorithm provider
        KeyPairGenerator key_pair_generator = KeyPairGenerator.getInstance(encryption_algorithm);
        // initialize a new key pair generator of type RSA
        SecureRandom rng = SecureRandom.getInstance(hashing_algorithm, hash_algorithm_provider);
        // initialize a new secure random number generator
        rng.setSeed(_seed);
        // set our seed
        key_pair_generator.initialize(1024, rng);
        // start generating

        this.key_pair = key_pair_generator.generateKeyPair();
        this.public_key = key_pair.getPublic();
        this.private_key = key_pair.getPrivate();
        // binds the generated keys to itself
    }

    public PublicKey getPublicKey() throws Exception { return this.public_key; }
    public void setPublic_key(PublicKey _pubKey) { this.public_key = _pubKey; }

    public byte[] signData(byte[] _unsignedData) throws Exception {
        this.signature.initSign(this.private_key);
        // signature belonging to this process signs with private key
        this.signature.update(_unsignedData);
        // signature belonging to this process updates the unsigned data after signing
        return this.signature.sign();
        // return byte array of signed data
    }

    public boolean verifySig(byte[] _unsignedData, byte[] _signedData) throws Exception {
        this.signature.initVerify(this.public_key);
        // verify signature from running process with its respective public key
        this.signature.update(_unsignedData);
        // update the unsigned data
        return this.signature.verify(_signedData);
        // return our verified signature
    }
}

/*
    Worker that handles incoming Public Keys
 */
class PublicKeyWorker extends Thread
{
    Socket keySocket;
    // only member variable and will remain local

    PublicKeyWorker(Socket _socket)
    {
        keySocket = _socket;
        // constructor to assign argument as key socket
    }

    public void run()
    {
        System.out.println("In Public Key Client");
        // print to console when the public key worker connects to the server
        ObjectInputStream object_input;
        // declare an object input stream variable input
        if (bcE.ProcessID == 2) { return; }
        // exit out of code block if process 2 is up and running
        try
        {
            object_input = new ObjectInputStream(this.keySocket.getInputStream());
            // initialize new object input stream
            try
            {
                PublicKey public_key = (PublicKey) object_input.readObject();
                // declare and initialize a new public key for the incoming block
                System.out.println("Process " + bcE.ProcessID + " got new key: " + public_key.toString());
                // print out which process has been assigned a new public key

                if (DemonstrateUtils.getKeyManager() == null)
                {
                    System.out.println("Public Key set");
                    // print ou that the public key is being set
                    DemonstrateUtils.setManageKeys(new KeyManager(public_key));
                    // set the public key
                }
            } catch (Exception exception)
            {
                System.out.println("Server Error when setting Public Keys");
                exception.printStackTrace();
                System.out.println();
            } finally
            {
                object_input.close();
                // safely close the object input stream
                this.keySocket.close();
                // close the keysocket for the respective process
            }
        } catch (IOException exception)
        {
            System.out.println("Socket Error ");
            exception.printStackTrace();
            System.out.println();
            // print out any exceptions caught out to console to debug
        }
    }
}

class ManageKeyWorker extends Thread
{
    Socket socket;
    // declare socket member variable
    KeyManager manageKeys;
    // declare key manager variable

    ManageKeyWorker(Socket _socket, KeyManager _manageKeys)
    {
        this.socket = _socket;
        // bind to socket being passed in constructor
        this.manageKeys = _manageKeys;
        // bind to manageKeys being passed in constructor
    }

    public void run()
    {
        System.out.println("In Key Manager Key Client");
        // print out to the console when we beign running the ManageKeyWorker
        PrintStream output_printStream = null;
        // declare and initialize a new print stream to null
        BufferedReader buffered_reader = null;
        // declare and initialize a buffered reader variableto null

        try
        {
            buffered_reader = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
            // initialize the buffered reader input object to a new buffered reader and pass the right socket for each respective process
            try
            {
                StringBuilder recordBlock = new StringBuilder();
                // declare a new record block variable and initialize to an empty string
                String incomingBlock;
                // declare a string variable to hold incoming blocks
                while ((incomingBlock = buffered_reader.readLine()) != null)
                {
                    recordBlock.append(incomingBlock);
                    // add incoming block data to the record block string
                }

                BlockRecord block_to_send = DemonstrateUtils.DeserializeBlockRecord(recordBlock.toString());
                // deserialize back into java object and grab the block about to be multicast
                byte[] block_hashArr = DemonstrateUtils.getHashByteArray(DemonstrateUtils.SerializeBlockRecord(block_to_send));
                // store the hashed data block in the byte array blockHashArr

                StringBuilder sb = new StringBuilder();
                // declare and initialize a new String Buffer
                for (byte b : block_hashArr) { sb.append(Integer.toString((b & 0xFF) + 0x100, 16).substring(1)); }
                // concatenate blockHAsh in the string buffer

                String SHA256_string = sb.toString();
                // save the SHA256 hash string in a string variable
                block_to_send.setHashedBlock(SHA256_string);
                // set the block about to be sent with the sha256 hashed string

                byte[] signed_block_byteArr = this.manageKeys.signData(block_to_send.getBlockID().getBytes(StandardCharsets.UTF_8));
                // declare and initialize a byte array to store the newly signed block
                block_to_send.setSignedBlockID(Base64.getEncoder().encodeToString(signed_block_byteArr));
                // set the signed block ID on the send block

                for (int i = 0; i < bcE.ProcessCount ; i++)
                {
                    if (block_to_send.getBlockID().equals("0")) // number of our fake block without a real BlockID
                    {
                        System.out.println("Sending *Fake Block* to Process: " + i);
                        // print out to console to which process we are sending the fake block
                    }
                    else
                    {
                        System.out.println("Sending Unverified Block to Process: " + i);
                        // print to console to which process we are sending the real unverified block
                    }

                    Socket UVBserverSocket = new Socket(bcE.serverName, Ports.getUVBServerPort());
                    // declare a new unverified block server socket and feed it the proper port for the respective process
                    output_printStream = new PrintStream(UVBserverSocket.getOutputStream());
                    // initialize a new print stream from server and store it in variable output
                    output_printStream.println(DemonstrateUtils.SerializeBlockRecord(block_to_send));
                    // serialize our send block for json multicast
                    output_printStream.flush();
                    // flush the print stream
                    output_printStream.close();
                    // close the print stream
                    UVBserverSocket.close();
                    // close the unverified block server socket
                }
            } catch (Exception exception)
            {
                System.out.println("Error when attempting to multicast ");
                exception.printStackTrace();
                System.out.println();
            } finally {
                this.socket.close();
                // safely close the specific process socket
                buffered_reader.close();
                // safely close the buffered reader input
            }
        } catch (IOException exception)
        {
            System.out.println("Socket Error in ManageKeyWorker" );
            exception.printStackTrace();
            System.out.println();
        }
    }
}

class BlockchainWorker extends Thread
{
    Socket blockchain_worker_socket;
    // private member variable socket for our blockchain worker
    static final Lock serializeLock = new ReentrantLock();
    // declare a final Lock variable to ensure avoid concurrency errors
    static boolean isSerialized = false;
    // declare a boolean variable to check if a block record has been serialized
    BlockchainWorker(Socket _sock)
    {
        this.blockchain_worker_socket = _sock;
        // bind process specific socket to _sock in constructor
    }

    public void run()
    {
        System.out.println("In Blockchain Client");
        // print to the console when we begin running the BlockchainWorker
        BufferedReader buffered_reader_input = null;
        // declare and initialize a new input buffered reader to null
        try
        {
            buffered_reader_input = new BufferedReader(new InputStreamReader(this.blockchain_worker_socket.getInputStream()));
            // initialize the buffered reader input with input stream reader for current process's socket
            try
            {
                String new_block_recordList = "";
                // declare a new ledger variable to hold incoming block information and initialize to an empty string
                String incomingBlock;
                // declare a string variable to hold the data in the incoming block
                while ((incomingBlock = buffered_reader_input.readLine()) != null)
                {
                    new_block_recordList += incomingBlock;
                    // add the read incoming block to the new ledger string
                }

                bcE.recordList = DemonstrateUtils.DeserializeBlockList(new_block_recordList);
                // update the main blockchain ledger by deserializing the newly concatenated ledger

                if (bcE.ProcessID == 0)
                {
                    this.exportLedger();
                    // export the final blockchain ledger from process 0
                }
            } catch (Exception exception)
            {
                System.out.println("Error encountered in Blockchain Server");
                exception.printStackTrace();
                System.out.println();
            } finally
            {
                this.blockchain_worker_socket.close();
                // close the particular process' socket
                buffered_reader_input.close();
                // safely close the buffered reader input connection
            }
        } catch (IOException exception)
        {
            System.out.println("Socket Error in Blockchain Worker");
            exception.printStackTrace();
            System.out.println();
        }
    }

    private void exportLedger()
    {
        System.out.println("Exporting last Updated Blockchain Ledger");
        // print to the console when this method begins to execute
        try
        {
            BufferedWriter bufferedWriter = null;
            // declare a buffered writer variable and temporarily initialize to null
            String serializedBlock;
            // declare a string to hold the serialized block object
            serializeLock.lock();
            // lock serializables while manipulating to avoid critical failure
            try
            {
                serializedBlock = this.SerializeBlockRecord(bcE.recordList);
                // store the current process' serialized block record in the serializedBlock variable
            } finally
            {
                serializeLock.unlock();
                // safely unlock serializable after critical section
            }

            try
            {
                System.out.println("Blockchain Ledger Size: " + bcE.recordList.size());
                // print the ledger size out to console
                bufferedWriter.write(serializedBlock);
                // write the serialized block
                bufferedWriter.flush();
                // flush the buffered writer
            } catch (IOException exception)
            {
                System.out.println("IO Exception caught while exporting Ledger");
                exception.printStackTrace();
                System.out.println();
            } finally
            {
                bufferedWriter.close();
                // safely close the buffered writer
            }
        } catch (Exception exception)
        {
            System.out.println("Exception caught while attempting to export Ledger");
            exception.printStackTrace();
            System.out.println();
        }
    }

    private String SerializeBlockRecord(ArrayList<BlockRecord> _records)
    {
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        // declare and initialize new gson builder object
        return gson.toJson(_records);
        // return the serialized blocks
    }
}


class BlockchainServer implements Runnable
{
    int port;
    // declare private member variable port

    BlockchainServer(int _port)
    {
        this.port = _port;
        // bind the blockchain server to port passed as argument
    }

    public void run()
    {
        int q_len = 6;
        // number of opsys requests
        Socket socket;
        // declare a new socket
        System.out.println("Starting the Blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort) + "\n");
        try
        {
            ServerSocket serverSocket = new ServerSocket(port, q_len);
            // declare and implement new server socket taking in the blockchain server port
            while (true)
            {
                try
                {
                    socket = serverSocket.accept();
                    // accept incoming connections from client
                    new BlockchainWorker(socket).start();
                    // spawn new blockchain worker to handle requests
                } catch (Exception exception) { }
            }
        } catch (IOException ioException)
        {
            System.out.println("IO Exception caught when attempting to start the Blockchain Worker");
            ioException.printStackTrace();
            System.out.println();
            // print out caught exceptions
        }
    }
}


class UVBServer implements Runnable
{
    int port;
    // private member variable port

    UVBServer(int _port)
    {
        this.port = _port;
        // constructor to bind port passed to UVBserver in constructor
    }

    public static Comparator<BlockRecord> BlockTimeStampComparator = new Comparator<BlockRecord>()
    {
        @Override
        public int compare(BlockRecord _b1, BlockRecord _b2)
        {
            String s1 = _b1.getTimeStamp();
            // compare string 1 to block 1
            String s2 = _b2.getTimeStamp();
            // compare string 2 to block 2
            if (s1 == s2)
            // return true if s1 equals s2
            {
                return 0;
            }

            if (s1 == null)
            // return false if s1 is null
            {
                return -1;
            }

            if (s2 == null)
            // return false if s2 is null
            {
                return 1;
            }

            return s1.compareTo(s2);
            // return our comparison
        }
    };

    public void run()
    {
        int q_len = 6;
        // number of OpSys requests to queue
        Socket socket;
        // declare new socket
        System.out.println("Starting the Unverified Block Server input thread using: " + Integer.toString(Ports.UVBServerPort));
        // print to the client that we are starting up the UVBServer input thread
        try
        {
            ServerSocket UVBServerSocket = new ServerSocket(port, q_len);
            // declare and initialize new server socket and pass in the unverified block server port number and opsys request q_len
            while (true)
            {
                socket = UVBServerSocket.accept();
                // accept incoming connections when unverified block is sent
                System.out.println("*New Connection to the Unverified Block Server*");
                // print out a notification to the client that we received a new connection to the UVBServer
                new UVBWorker(socket).start();
                // spawn new unverified block worker to handle new requests
            }
        } catch (IOException ioe)
        {
            System.out.println("IO Exception caught when attempting to run Unverified Block Server");
            ioe.printStackTrace();
            System.out.println();
            // notify client that an exception was caught
        }
    }
}


class PublicKeyServer implements Runnable
{
    int port;
    // private member variable port

    PublicKeyServer(int _port)
    {
        this.port = _port;
        // bind port passed to the public key server in constructor
    }

    public void run()
    {
        int q_len = 6;
        // number of OpSys requests
        Socket keySocket;
        // declare new socket key socket
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
        // print out to the console which port is being used for the key server port

        try
        {
            ServerSocket serverSocket = new ServerSocket(port, q_len);
            // declare and initialize new server socket for the Public Key Server port
            System.out.println("Public Key Server Connected");
            // print that a process has connected to the public key server
            while (true)
            {
                keySocket = serverSocket.accept();
                // keep accepting incoming public keys
                new PublicKeyWorker(keySocket).start();
                // spawn our worker to begin handling those incoming keys
            }
        } catch (IOException ioe)
        {
            System.out.println("DEBUG HERE (right after starting key server input thread");
            ioe.printStackTrace();
            System.out.println();
        }
    }
}

class ManageKeyServer implements Runnable
{
    int port = 6000;
    // declare private member variable port and initialize to 1524

    public void run()
    {
        int q_len = 6;
        // number of OpSys request
        Socket socket;
        // declare new socket variable

        try
        {
            ServerSocket serverSocket = new ServerSocket(port, q_len);
            // declare and initialize new serversocket for Manage Key Server
            System.out.println("Managing Keys Server waiting on Port: " + port );
            // print out that the ManageKeyServer is up and waiting for key requests
            System.out.println("Generating Key Pair");
            // print that key pair generation has initialized
            KeyManager manageKeys = new KeyManager();
            // declare and initialize a new KeyManager object to manage keys
            try
            {
                manageKeys.generateKeyPair(777);
                // generate pub/priv key pair with manageKeys object
            } catch (Exception exception)
            {
                System.out.println("Exception caught when attempting to generate new Key Pair");
                exception.printStackTrace();
                System.out.println();
            }

            DemonstrateUtils.setManageKeys(manageKeys);
            // set this to be in charge of managing keys in demonstrate utils
            DemonstrateUtils.KeySend(Ports.getKeyServerPortsArray());
            // multicast public key to all processes in the consortium

            while (true)
            {
                socket = serverSocket.accept();
                // accept incoming keys
                new ManageKeyWorker(socket, manageKeys).start();
                // spawn manage key worker to handle key requests
            }
        } catch (Exception exception)
        {
            System.out.println("Exception caught when attempting to start the Manage Keys Worker");
            exception.printStackTrace();
            System.out.println();
        }
    }
}

class DemonstrateUtils
{
    static final int iFNAME = 0;
    static final int iLNAME = 1;
    static final int iDOB = 2;
    static final int iSSNUM = 3;
    static final int iDIAG = 4;
    static final int iTREAT = 5;
    static final int iRX = 6;

    private static KeyManager manageKeys = null;
    // declare and initialize key management var manageKeys as a private member variable of DemonstrateUtils class

    public static KeyManager getKeyManager() { return manageKeys; }
    public static void setManageKeys(KeyManager _manageKeys) { manageKeys = _manageKeys; }

    public static ArrayList<BlockRecord> ReadFile(String _fileName, int _processID) {
        ArrayList<BlockRecord> block_record_arrayList = new ArrayList<BlockRecord>();
        // declare and inititialize new ArrayList that contains BlockRecords
        BlockRecord temp_record;
        // declare new temp block record variable
        String current_processID = Integer.toString(_processID);
        // save our process id from argument in string format
        int n = 0;
        try (BufferedReader buffered_reader_input = new BufferedReader(new FileReader(_fileName))) {
            String input;
            // declare new input string to read in lines
            String[] tokens = new String[10];
            // new string array to store our tokenized input
            String string_uuid;
            // declarestring variable to hold the string version of the unique identifier
            UUID binary_uuid;
            // declare binary uuid variable
            while ((input = buffered_reader_input.readLine()) != null) {
                BlockRecord blockRecord = new BlockRecord();
                // declare and initialize new BlockRecord object
                try {
                    Thread.sleep(999);
                } catch (InterruptedException exception){ }

                Date new_date = new Date();
                // declare new date variable to build timestamp
                String t1 = String.format("%1$s %2$tF.%2$tT", "", new_date);
                // format the timestamp
                String timestamp_string = t1 + "." + bcE.ProcessID;
                // build the time stamp string with the calling process' id
                System.out.println(timestamp_string);
                // print the newly minted timestamp to the console, all priority queue sorting will be done by timestamp

                string_uuid = new String(UUID.randomUUID().toString());
                // build the new string uuid
                blockRecord.setBlockID(string_uuid);
                // set the block ID with the string formatted uuid
                blockRecord.setCreatingProcessID(current_processID);
                // set the PID for the current process
                tokens = input.split(" +");
                // tokenize our input line by splitting into an string array
                blockRecord.setFirstName(tokens[iFNAME]);
                blockRecord.setLastName(tokens[iLNAME]);
                blockRecord.setDOB(tokens[iSSNUM]);
                blockRecord.setSSN(tokens[iDOB]);
                blockRecord.setDiag(tokens[iDIAG]);
                blockRecord.setTreat(tokens[iTREAT]);
                blockRecord.setRX(tokens[iRX]);
                // fill the block record with the data read from one of the three input files

                block_record_arrayList.add(blockRecord);
                // add the record to the array list
                n++;
                //iterate
            }
        } catch (Exception exception) {
            System.out.println("Error reading input file...");
            exception.printStackTrace();
            System.out.println();
        }

        System.out.println( n + " records read.");
        // print out to the console how many records have been read
        System.out.println("Names from input: " );
        // Print out the header for the patient names we are about to print

        Iterator<BlockRecord> record_iterator = block_record_arrayList.iterator();
        // create a new iterator to loop through record list
        while (record_iterator.hasNext())
        {
            temp_record = record_iterator.next();
            // assign temp record the index in the record list
            System.out.println(temp_record.getTimeStamp() + " " + temp_record.getFirstName() + " " + temp_record.getLastName());
        }
        System.out.println("");
        // print to the console to help with formatting

        record_iterator = block_record_arrayList.iterator();
        // reset iterator
        System.out.println("The Shuffled List: ");
        Collections.shuffle(block_record_arrayList);
        // shuffle block record array list for funsies and print it out to see priority queue in action
        while (record_iterator.hasNext())
        {
            temp_record = record_iterator.next();
            // assign temp record the index in the record list
            System.out.println(temp_record.getTimeStamp() + " " + temp_record.getFirstName() + " " + temp_record.getLastName());
        }
        System.out.println("");
        // print to the console to help with formatting

        record_iterator = block_record_arrayList.iterator();
        // reset iterator
        System.out.println("Placing shuffled record list in blockchain priority queue");

        n = 0;
        // reset our counter
        while (record_iterator.hasNext())
        {
            bcE.BlockchainPriorityQueue.add(record_iterator.next());
            // add block records into the priority queue
            n++;
            // iterate to know how many records end up in the priority queue for next loop
        }

        System.out.println("Restored order in blockchain priority queue: ");
        //while (true)
        for (int i = 0; i < n; i++)
        {
            temp_record = bcE.BlockchainPriorityQueue.poll();
            // pops the next record in queue
        }
        n = 0;
        // reset iterator counter variable

        return block_record_arrayList;
    }

    public static String SerializeBlockRecord(ArrayList<BlockRecord> _blockRecords) throws Exception
    // for serializing multiple records
    {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        // declare and initialize a new google gson object to build our JSON string
        return gson.toJson(_blockRecords);
        // return our new JSON string
    }

    public static String SerializeBlockRecord(BlockRecord _blockRecord) throws Exception
    // for a single record
    {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        // declare and initialize a new google gson object to build our JSON string
        return gson.toJson(_blockRecord);
        // return our new JSON string
    }

    public static BlockRecord DeserializeBlockRecord(String _blockRecord) throws Exception
    {
        return new Gson().fromJson(_blockRecord, BlockRecord.class);
        // deserialize by building a new gson fromJson using our arg string and the BlockRecord runnable
    }

    public static ArrayList<BlockRecord> DeserializeBlockList(String _recordList) throws Exception
    {
        Type tokenList = new TypeToken<ArrayList<BlockRecord>>(){}.getType();
        // declare and initialize a new variable of class Type to help tokenize our ledger of blockchain records
        return new Gson().fromJson(_recordList, tokenList);
        // return the deserialized ledger of blockchain record tokens
    }

    public static void UnverifiedSend(BlockRecord _uvb) {
        try {
            Socket UnverifiedBlockSocket = null;
            // declare a unbverified block socket to hold client connection to UVBServer for each process
            PrintStream output = null;
            // declare and initialize a new printstream to server
            try {
                UnverifiedBlockSocket = new Socket(bcE.serverName, Ports.KeyManagementPort);
                // bind the UVB socket to the key management port before being signed
                output = new PrintStream(UnverifiedBlockSocket.getOutputStream());
                // initialize our print stream to send unverified blocks
                if (_uvb == null) {
                    BlockRecord blockRecord = new BlockRecord();
                    // declare and initialize a new block record object
                    blockRecord.setBlockID("0");
                    // genesis block
                    blockRecord.setCreatingProcessID(Integer.toString(bcE.PID));
                    // set the creating process ID to be included in block header when printed
                    System.out.println("Unverified Block being sent for verification");
                    // print to the console that a new uvb is being sent
                    output.println(SerializeBlockRecord(blockRecord));
                    // send block record header out to server
                    output.flush();
                    // flush our print stream
                } else {
                    output.println(SerializeBlockRecord(_uvb));
                    // send unverified block record to the server
                    output.flush();
                    // flush the print stream to the server
                }
            } catch (IOException exception) {
                System.out.println("Error sending Unverified Block...");
                exception.printStackTrace();
                System.out.println();
            } finally {
                output.close();
                UnverifiedBlockSocket.close();
                // close our socket and print stream
            }
        } catch (Exception exception) {
            System.out.print("Error! Could not send Unverified Block...");
            exception.printStackTrace();
            System.out.println();
        }
    }

    public static void KeySend(int[] _keyServerPorts)
    {
        Socket socket;
        // declare a new socket
        ObjectOutputStream toServer;
        // declare a new Object Output Stream variable
        for(int i = 0; i < _keyServerPorts.length; i++) {
            try {
                socket = new Socket(bcE.serverName, _keyServerPorts[i]);
                // initialize a new socket for each incoming process taking in each's respectine port number
                toServer = new ObjectOutputStream(socket.getOutputStream());
                // initialize a new object output stream to send the public keys
                System.out.println("Now sending the public keys " + i);
                // print to console that the pub key is being sent
                toServer.writeObject("(FakeKeyProcess) Sending public keys: " + manageKeys.getPublicKey() + "\n");
                // print out fake key process/ well real key process now
                toServer.flush();
                // flush the object output stream
                socket.close();
                // close off socket connections
            } catch (Exception exception) {
                System.out.println("Connection Exception\nCould not send keys: " + i);
                exception.printStackTrace();
                // print caught exceptions to the console
                return;
            }
        }
    }

    public static byte[] getHashByteArray(String _toHash) throws Exception
    {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        // declare a new message digest to store the hash
        return messageDigest.digest(_toHash.getBytes("UTF-8"));
        // return hash in byte array format
    }

/*
    public static String mineBlock(int _prefix)
    {
        String prefixString = new String(new char[_prefix]).replace('\0', '0');
        /*
         //* declare and intialialize our prefix string to a new string containing our prefix integer with '\0' replaced
         //* by '0' to represent the prefix we are looking for


        while (!bcE.hash.substring(0, _prefix).equals(prefixString))
        // while we do not have our desired solution
        {
            bcE.nonce++;
            // increment our nonce
            bcE.hash = bcE.calculateBlockHash();
            // and calculate the hash
        }
        return bcE.hash;
        // return our winning hash w=once we find our desired prefixString
    }

 */


    public static void doWork() throws Exception
    {
        System.out.println("Now simulating work: ");
        // print to the console to show the beginning of *work* simulation

        int rVal = 77;
        // new arbitrary value
        int tenths = 0;
        // declare and intitialize tenth var to 0
        Random random = new Random();
        // declare and initialize a new random variable

        for (int i = 0; i < 1000; i++)
        // our safe upper limit is 1000
        {
            Thread.sleep(100);
            // our fake work
            rVal = random.nextInt(100);
            // higher the bound means more work
            System.out.println(".");

            if (rVal < 10)
            // the lower the threshold means more work in this case
            {
                tenths = i;
                break;
            }
        }
        System.out.println(" <-- we did " + tenths + " tenths of a second of *work*\n");
        // print how long it took us to solve the fake work to the console

        //final byte[] cipherText = encrypt(SHA256string, keyPair.getPublic()); //dont need for this assignment
        // encrypt hash string using public key
    }
}

class UVBConsumer implements Runnable {
    public void run() {
        BlockRecord blockRecord;

        System.out.println("Now in Unverified Block Consumer");

        try {
            while (true) {
                boolean hasBlock = false;
                // declare a new bool adn set to false for if there is a block
                blockRecord = bcE.BlockchainPriorityQueue.take();
                // take a block from our priority queue and save it in our block record object
                System.out.println("Unverified Blockchain Consumer received a new UVB: " + DemonstrateUtils.SerializeBlockRecord(blockRecord));
                // print out that a new unverified block was received by UVB consumer and serialize said block
                for (BlockRecord ledger : bcE.recordList) {
                    if (ledger.getBlockID().compareToIgnoreCase(blockRecord.getBlockID()) == 0) {
                        hasBlock = true;
                        break;
                    }
                }
                if (!validBlock(blockRecord)) {
                    continue;
                }
                try {
                    int currentBlockNum = bcE.recordList.size() + 1;
                    // set the current blocks number in the next available index of the ledger
                    blockRecord.setBlockNum(currentBlockNum);
                    // set the block num in the block record object
                    blockRecord.setVerificationProcessID(Integer.toString(bcE.ProcessID));
                    // set the verification process id to the current process ID
                    String previousHash;
                    // declare previous hash variable
                    if (!blockRecord.getBlockID().equals("0") && bcE.recordList.size() != 0) {
                        int previousBlockNumber = bcE.recordList.size() - 1;
                        // set the previous blocks number to the last index
                        previousHash = bcE.recordList.get(previousBlockNumber).getPreviousHash();
                    } else {
                        //previousHash = DatatypeConverter.printHexBinary(DemonstrateUtils.getHashByteArray(blockRecord.getHashedBlock()));
                        previousHash = Base64.getEncoder().encodeToString(DemonstrateUtils.getHashByteArray(blockRecord.getHashedBlock()));
                        // turn the hash byte array into a string and set it as previous hash
                    }
                    for (int i = 0; i < 333; i++) {
                        String randSeed = this.generateRandomHash();
                        // new random string
                        String concatenatedString = previousHash + randSeed;
                        // concatenate random sring with the previosu hash and save it concatenateString variable
                        String newHash = Base64.getEncoder().encodeToString(DemonstrateUtils.getHashByteArray(blockRecord.getHashedBlock()));

                        // convert our concatenated string into byte array and then then to a string to save in new hash variable
                        if (this.isWinningHash(newHash)) {
                            blockRecord.setRandomSeed(randSeed);
                            // set the random seed to reflect that the work was competed for and solved
                            blockRecord.setPreviousHash(concatenatedString);
                            // set the previous blocks hash
                            break;
                            // quit out once we have the hashes set in block record object
                        }

                        for (BlockRecord ledger : bcE.recordList) {
                            if (ledger.getBlockID().compareToIgnoreCase(blockRecord.getBlockID()) == 0) {
                                System.out.println("This Block has already been verified...\nWaiting for new Block");
                                hasBlock = true;
                                break;
                            }
                        }
                        if (hasBlock) {
                            break;
                            // exit out if hasBlock is already true
                        }
                    }
                } catch (Exception exception) {
                    System.out.println("Error when performing work....");
                    exception.printStackTrace();
                    System.out.println();
                }
                if (!hasBlock) {
                    for (BlockRecord ledger : bcE.recordList) {
                        if (ledger.getBlockID().compareToIgnoreCase(blockRecord.getBlockID()) == 0) {
                            System.out.println("((2)) Block already verified... Waiting");
                            hasBlock = true;
                            break;
                        }
                    }
                    if (!hasBlock) // if a process did not solve yet just add the record and count it as verified
                    {
                        bcE.recordList.add(blockRecord);
                        this.sendVerified();
                    }
                }
            }
        } catch (Exception exception) {
            System.out.print("Exception caught when attempting to verify Block...");
            exception.printStackTrace();
            System.out.println();
        }
    }

    private boolean isWinningHash(String _winningHash) throws Exception {
        int prefix = Integer.parseInt(_winningHash.substring(0, 4), 16);
        // turn our potential winning hash string into hexadecimal and then parse int
        return prefix < 30000;
        // if the prefix is less than 30000 then it is the winning prefix
    }

    private String generateRandomHash() throws Exception {
        String tempString = "John Lamb" + "Sand Meet" + "Rocket Dog" + "q34r9q9ruur" + "rooster";
        // I'm really struggling so I'm making my own string to hash in this method, very insecure I know
        tempString += generateRandomString();
        // add a big heaping help of ACTUAL randomness into our hash!
        String SHA256string = "";
        // declare a new sha256string as an empty string
        MessageDigest ourMD = MessageDigest.getInstance("SHA-256");
        ourMD.update(tempString.getBytes());
        // turn our read-in block data in a string buffer into a string to hash
        byte[] byteData = ourMD.digest();
        // digest the data into a byte array
        StringBuffer sb2 = new StringBuffer();

        for (byte byteDatum : byteData) {
            sb2.append(Integer.toString((byteDatum & 0xff) + 0x100, 16).substring(1));
        }
        SHA256string = sb2.toString();
        return SHA256string;
        // return our new sha256string hash
    }

    public static String generateRandomString() throws Exception
    {
        Random random = new SecureRandom();
        // declare a new random so our hash is a little varied each time
        StringBuilder stringBuilder = new StringBuilder();
        // declare and intialize new string builder
        int Length = 45;
        // a very presidential length
        char someChar;
        for (int i = 0; i < Length; i++)
        {
            someChar = (char) (random.nextInt(777) - 123);
            stringBuilder.append(someChar);
            // append our randomness to the string builder and see what we get
        }
        return stringBuilder.toString();
    }


    public void sendVerified() throws Exception
    {
        PrintStream output;
        // declare new print stream variable
        Socket socket;
        // declare new socket variable

        int[] blockchainServerPorts = Ports.getBlockchainServerPortsArray();
        // fill an int array with the blockchain server ports currently in use
        for (int i = 0; i < blockchainServerPorts.length; i++)
        {
            socket = new Socket(bcE.serverName, blockchainServerPorts[i]);
            // bind the socket to the correct process port
            output = new PrintStream(socket.getOutputStream());
            // initialize print stream
            System.out.println("Sending updated Ledger");
            // tell the console that the new ledger is being multicast
            output.println(DemonstrateUtils.SerializeBlockRecord(bcE.recordList));
            // multicast the serialized block record
            output.flush();
            // flush the print stream
            output.close();
            // close the connection
            socket.close();
            // close socket connection
        }
    }
    public boolean validBlock(BlockRecord _blockRecord) throws Exception {
        byte[] signedBlockArr = Base64.getDecoder().decode(_blockRecord.getSignedBlockID());
        // declare an array to hold the signed block in byte array format
        byte[] signedBlock = Base64.getDecoder().decode(_blockRecord.getSignedBlockID());
        // declare an array to hold the signed block in byte array format

        if (!DemonstrateUtils.getKeyManager().verifySig(_blockRecord.getBlockID().getBytes(), signedBlockArr)
                || !DemonstrateUtils.getKeyManager().verifySig(_blockRecord.getHashedBlock().getBytes(), signedBlock)) {
            System.out.println("SIGNATURE INVALID");
            // print out error to console
            return false;
        }
        return true;
    }
}

class UVBWorker extends Thread
{
    Socket socket;
    // socket member variable

    UVBWorker (Socket _sock)
    {
        this.socket = _sock;
        // bind socket to argument _sock
    }

    public void run()
    {
        System.out.println("Unverified Block Worker connected");
        // print out debugging statement to know where we are in console
        BufferedReader bufferedReader = null;
        // declare new bufferedReader object
        try
        {
            bufferedReader = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
            // initialize bufferedReader for desgnated socket
            try
            {
                System.out.println("Received new Unverified Block");
                // print out when a new UVB is received
                String newBlock = "";
                // declare a string to hold the new block information
                String incomingBlock;
                // declare a variable to hold the block being received
                while ((incomingBlock = bufferedReader.readLine()) != null)
                {
                    newBlock += incomingBlock;
                    // add incoming block information to the new block
                }
                bcE.BlockchainPriorityQueue.put(DemonstrateUtils.DeserializeBlockRecord(newBlock));
                // add the new block into the priority queue
                System.out.println("Unverified block: " + newBlock + " has been placed in the Blockchain Priority Queue");
            } catch (Exception exception)
            {
                System.out.println("Server Error" );
                exception.printStackTrace();
                System.out.println();
            } finally
            {
                bufferedReader.close();
                // close the bufferedReader
                this.socket.close();
                // close the connected socket for the respective process
            }
        } catch (Exception exception)
        {
            System.out.println("IO Exception, failed to bind socket ");
            exception.printStackTrace();
            System.out.println();
        }
    }
}


public class bcE
{
    public static final int ProcessCount = 3;
    // final int member variable that holdsthe number of processes we plan to run
    public static final int PID = 0;
    // final member variable to set the process ID to 0 by default
    public static final String serverName = "localhost";
    // final member variable to hold servername and save it as a string
    public static Comparator<BlockRecord> BlockTimeStampComparator = new Comparator<BlockRecord>()
    {
        @Override
        public int compare(BlockRecord _b1, BlockRecord _b2)
        {
            String s1 = _b1.getTimeStamp();
            // compare string 1 to block 1
            String s2 = _b2.getTimeStamp();
            // compare string 2 to block 2
            if (s1 == s2)
            // return true if s1 equals s2
            {
                return 0;
            }

            if (s1 == null)
            // return false if s1 is null
            {
                return -1;
            }

            if (s2 == null)
            // return false if s2 is null
            {
                return 1;
            }

            return s1.compareTo(s2);
            // return our comparison
        }
    };
    // new comparator object to compare records
    public static final PriorityBlockingQueue<BlockRecord> BlockchainPriorityQueue = new PriorityBlockingQueue<BlockRecord>(100, BlockTimeStampComparator);
    // declare a final blocking priority queue that is concurrent
    public static ArrayList<BlockRecord> recordList = new ArrayList<>();
    // declare and initialize a new array list full of BlockRecords. This will act as the ledger
    public static int ProcessID = 0;
    // declare new processID member variable and initialize to zero
    public static String fakeBlock = "[first block]";
    // declare our dummy genesis block
    public static  String FILENAME;
    // declare a string variable to hold the input file name

    public static void main(String a[])
    {
        Ports.setPorts();
        // set all ports up here

        /*
         * Added the extra functionality of randomly generating five block and populating them with random strings in the makeBlock() method.
         * Will certainly be random nonsense, but wanted to show dynamic block building other than from the input files
         */
        if (a.length > 2)
        {
            BlockRecord rand_record = new BlockRecord();
            System.out.println("Secret Random Block generation initiated\nUsing Process N");
            for (int i = 0; i < 5; i++)
            {
                rand_record = makeBlock();
                // assign the random block record whtever is spit out of my makeblock function
                Date new_date = new Date();
                // declare new date variable to build timestamp
                String t1 = String.format("%1$s %2$tF.%2$tT", "", new_date);
                // format the timestamp
                String timestamp_string = t1 + "." + bcE.ProcessID;
                // build the time stamp string with the calling process' id
                rand_record.setTimeStamp(timestamp_string);
                // set the random block timestamp so it can still be sorted into the queue
                System.out.println("Got random record:\n" + rand_record.getTimeStamp() + " " + rand_record.getFirstName() + " " + rand_record.getLastName());

                BlockchainPriorityQueue.add(rand_record);
                // add that badboy to the prority queue and see what happens
            }
        }

        /*
         * Check to see if the command line argument is empty
         * if so the process defaults to pid 0 and the welcome message is printed to console
         */
        if (a.length < 1)
        {
            System.out.println("Welcome\nUsing Bryce Jensen's Blockchain for Clark Elliott's CSC435\nRunning Process 0 by default\n");
            // print out a string to the console to inform the user which process is running. Blockchain starts on process 0 if no arguments are passed from command line.
            FILENAME = "/Users/bryce/bcE/BlockInput0.txt"; // make sure to change this back to just "BlockInput0.txt" before submission
            ProcessID = 0;
        }
        else if (a[0].equals("0"))
        // sets process number to 0 according to the command line argument
        {
            System.out.println("\nWelcome\nUsing Process 0\n");
            FILENAME = "/Users/bryce/bcE/BlockInput0.txt";  // make sure to change this back to just "BlockInput0.txt" before submission
            ProcessID = 0;
        }
        else if (a[0].equals("1"))
        // sets process number to 1 according to the command line argument
        {
            System.out.println("\nWelcome\nUsing Process 1\n");
            FILENAME = "/Users/bryce/bcE/BlockInput1.txt";   // make sure to change this back to just "BlockInput1.txt" before submission
            ProcessID = 1;
        }
        else if (a[0].equals("2"))
        // sets process number to 2 according to the command line argument
        {
            System.out.println("\nWelcome\nUsing Process 2\n");
            FILENAME = "/Users/bryce/bcE/BlockInput2.txt"; // make sure to change this back to just "BlockInput2.txt" before submission
            new Thread(new ManageKeyServer()).start();
            System.out.println("Starting up Key Manager thread on Process: " + bcE.ProcessID);
            ProcessID = 2;
        }
        else
        // sets process number to 0 by default if there is an invalid command limne argument
        {
            System.out.println("\nWelcome\nUsing Process 0\n");
            FILENAME = "BlockInput0.txt";
            ProcessID = 0;
        }


        Ports.setPorts(ProcessID);
        // set up ports for only the running process
        System.out.println("Ports: \n" + "Public Key Port: " + Ports.getKeyServerPort() + "\n"
        + "Unverified Block Server Port: " + Ports.getUVBServerPort() + "\n" +
                "Blockchain Server Port: " + Ports.getBlockchainServerPort());
        // print out port numbers to console
        System.out.println("\nINPUT FILE: " + FILENAME + "\n");
        // print which input file is being run on each process

        /*
         * here we attempt to start up each server thread
         * that our separate processes will be running
         */
        try
        {
            new Thread(new PublicKeyServer(Ports.getKeyServerPort())).start();
            // start up public key server thread
            new Thread(new UVBServer(Ports.getUVBServerPort())).start();
            // start up unverified block server thread
            new Thread(new UVBConsumer()).start();
            // start up new unverified block consumer thread
            new Thread(new BlockchainServer(Ports.getBlockchainServerPort())).start();
        } catch (Exception exception)
        {
            System.out.println("Exception caught, Failed to launch Servers ");
            exception.printStackTrace();
            System.out.println();
        }

        try
        {
            System.out.println("Listening for Public Key");
            // let the console know that the public key server is waiting for a public key
            while (DemonstrateUtils.getKeyManager() == null)
            {
                Thread.sleep(1001);
                // put the thread to sleep while we wait for all threads to start
            }
        } catch (Exception exception)
        {
            System.out.println("Exception caught while Threads were trying to sleep...");
            exception.printStackTrace();
            System.out.println();
        }

        BlockRecord fakeRecord = new BlockRecord();
        // make a new block record object to load in dummy blocks
        fakeRecord.setBlockNum(0);
        fakeRecord.setBlockID("Dummy Block 1");
        fakeRecord.setTimeStamp("0");
        // fill up the fake record to test unverified send from process 2

        if (ProcessID == 2)
        {
            DemonstrateUtils.UnverifiedSend(fakeRecord);
            // send the fake blocks when process to is up and running
        }

        ArrayList<BlockRecord> blockRecords = DemonstrateUtils.ReadFile(FILENAME, ProcessID);
        // declare a new array list and use to to store the contents of the designated block input file
        for (BlockRecord br: blockRecords)
        {
            DemonstrateUtils.UnverifiedSend(br);
            // send all block records read into array list blockRecords
        }
    }

    public static BlockRecord makeBlock()
    {
        BlockRecord br1 = new BlockRecord();
        BlockRecord br2 = new BlockRecord();
        BlockRecord br3 = new BlockRecord();
        BlockRecord br4 = new BlockRecord();
        BlockRecord br5 = new BlockRecord();

        br1.setUUID(generateUUID());
        br1.setFirstName("Marvin");
        br1.setLastName("BoJangleson");
        br1.setVerificationProcessID("Process " + bcE.ProcessID);
        br1.setPreviousHash("0");
        br1.setWinningHash(generateHash());
        // making a fake block to show some work since I can't seem to manage reading in and marshalling otand from JSON properly

        br2.setUUID(generateUUID());
        br2.setFirstName(generateRandomString());
        br2.setLastName(generateRandomString());
        br2.setVerificationProcessID("Process " + bcE.ProcessID);
        br2.setPreviousHash(br1.getWinningHash());
        br2.setWinningHash(generateHash());
        // another false block to make my blockchain more interesting and less sad

        br3.setUUID(generateUUID());
        br3.setFirstName(generateRandomString());
        br3.setLastName(generateRandomString());
        br3.setVerificationProcessID("Process " + bcE.ProcessID);
        br3.setPreviousHash(br2.getWinningHash());
        br3.setWinningHash(generateHash());
        // another false block

        br4.setUUID(generateUUID());
        br4.setFirstName(generateRandomString());
        br4.setLastName(generateRandomString());
        br4.setVerificationProcessID("Process " + bcE.ProcessID);
        br4.setPreviousHash(br3.getWinningHash());
        br4.setWinningHash(generateHash());
        // y uno otro

        br5.setUUID(generateUUID());
        br5.setFirstName(generateRandomString());
        br5.setLastName(generateRandomString());
        br5.setVerificationProcessID("Process " + bcE.ProcessID);
        br5.setPreviousHash(br4.getWinningHash());
        br5.setWinningHash(generateHash());
        // il fin

        Random random = new Random();
        int numPicker = random.nextInt(5);

        BlockRecord tempBlock = null;

        switch (numPicker)
        {
            case 1: {
                tempBlock = br1;
                break;
            }
            case 2: {
                tempBlock = br2;
                break;
            }
            case 3: {
                tempBlock = br3;
                break;
            }
            case 4: {
                tempBlock = br4;
                break;
            }
            case 5: {
                tempBlock = br5;
                break;
            }
        }
        return tempBlock;
    }

    public static UUID generateUUID()
    {
        UUID randomUUID = UUID.randomUUID();
        // just regular random uuid generation, trying to save my sanity by pulling this to its own method
        return randomUUID;
    }

    public static String generateRandomString()
    {
        Random random = new SecureRandom();
        // declare a new random so our hash is a little varied each time
        StringBuilder stringBuilder = new StringBuilder();
        // declare and intialize new string builder
        int Length = 45;
        // a very presidential length
        char someChar;
        for (int i = 0; i < Length; i++)
        {
            someChar = (char) (random.nextInt(777) - 123);
            stringBuilder.append(someChar);
            // append our randomness to the string builder and see what we get
        }
        return stringBuilder.toString();
    }

    public static String generateHash()
    {
        String tempString = "John Lamb" + "Sand Meet" + "Rocket Dog" + "q34r9q9ruur" + "rooster";
        // I'm really struggling so I'm making my own string to hash in this method, very insecure I know
        tempString += generateRandomString();
        // add a big heaping help of ACTUAL randomness into our hash!
        String SHA256string = "";
        // declare a new sha256string as an empty string
        try {
            MessageDigest ourMD = MessageDigest.getInstance("SHA-256");
            ourMD.update(tempString.getBytes());
            // turn our read-in block data in a string buffer into a string to hash
            byte[] byteData = ourMD.digest();
            // digest the data into a byte array
            StringBuffer sb2 = new StringBuffer();
            for (int i = 0; i < byteData.length; i++) {
                sb2.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
            }
            SHA256string = sb2.toString();
        } catch (NoSuchAlgorithmException x) {}
        // don't even bother with the debugging statements if this guy fails
        return SHA256string;
        // return our new sha256string hash
    }
}





