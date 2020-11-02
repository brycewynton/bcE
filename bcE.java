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
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;


class BlockRecord implements Comparable<BlockRecord>, Comparator<BlockRecord>
// block record class made serializable in order to send via socket. Will hold block data as we dynamically build our blockchain
{
    protected DataBlock DataBlock = new DataBlock();
    //
    @SerializedName(value = "BlockID")
    protected String BlockID;
    // will hold the blocks ID
    @SerializedName(value = "SignedBlockID")
    protected String SignedBlockID;
    // string to hgold our verified Block ID
    @SerializedName(value = "VerificationProcessID")
    protected String VerificationProcessID;
    // holds the ID of the process that verifies the block, or tries to
    @SerializedName(value = "CreatingProcessID")
    protected String CreatingProcessID;
    // holds a string version of the creating process id
    @SerializedName(value = "BlockNumber")
    protected int BlockNum = 0;
    // member var to hold the blocks number
    @SerializedName(value = "TimeStamp")
    protected String TimeStamp;
    // the blocks time stamp
    @SerializedName(value = "TimestampWhenAdded")
    protected String TimestampAdded;
    // timestamp string of when a block was added
    @SerializedName(value = "TimestampWhenVerified")
    protected String TimestampVerified;
    // timestamp string pf when a block is verified
    @SerializedName(value = "PreviousHash")
    protected String PreviousHash;
    // hash of the previous block
    @SerializedName(value = "uuid")
    protected UUID uuid;
    // how we will marshall data to JSON
    @SerializedName(value = "date")
    protected String Data;
    // the data contained in the block
    @SerializedName(value = "RandomSeed")
    protected String RandomSeed;
    // this will be our means of trying to verify the block
    @SerializedName(value = "WinningHash")
    protected String WinningHash;
    // the hash of our winning guess
    @SerializedName(value = "SHA256String")
    protected String SHA256String;
    // string to hold our unverified SHA256 hash
    @SerializedName(value = "SignedSHA256")
    protected String SignedSHA256;
    // string to hold the verified SHA256 string

    public String getTimeStamp()
    {
        return TimeStamp;
    }
    public void setTimeStamp(String _timeStamp)
    {
        bcE.TimeStamp = _timeStamp;
    }

    public String getTimeStampVerified()
    {
        return TimestampVerified;
    }

    public String getTimestampAdded()
    {
        return TimestampAdded;
    }

    public DataBlock getDataBlock()
    {
        return this.DataBlock;
    }

    public int getBlockNum()
    {
        return BlockNum;
    }
    public void setBlockNum(int _blockNum)
    {
        BlockNum = _blockNum;
    }

    public String getHashedBlock()
    {
        return SHA256String;
    }
    public void setHashedBlock(String _sha256string)
    {
        SHA256String = _sha256string;
    }

    public String getSignedSHA256()
    {
        return SignedSHA256;
    }
    public void setSignedSHA256(String _sha256string)
    {
        this.SignedSHA256 = _sha256string;
    }

    public String getCreatingProcessID()
    {
        return CreatingProcessID;
    }
    public void setCreatingProcessID(String _creatingProcess)
    {
        this.CreatingProcessID = _creatingProcess;
    }

    public String getBlockID()
    {
        return this.BlockID;
        // accessor to return block ID
    }
    public void setBlockID(String _BlockID)
    {
        this.BlockID = _BlockID;
        // accessor for setting the block ID
    }

    public String getSignedBlockID() {
        return this.SignedBlockID;
    }
    public void setSignedBlockID(String signedBlockID) {
        SignedBlockID = signedBlockID;
    }

    public String getVerificationProcessID()
    {
        return VerificationProcessID;
        // accessor to return verificationProcessID
    }
    public void setVerificationProcessID(String _VerificationProcessID)
    {
        this.VerificationProcessID = _VerificationProcessID;
    }

    public String getPreviousHash()
    {
        return this.PreviousHash;
    }
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

    @Override
    public int compareTo(BlockRecord _otherBlock)
    {
        return this.TimestampAdded.compareTo(_otherBlock.TimestampAdded);
    }
    @Override
    public int compare(BlockRecord _o1, BlockRecord _o2)
    {
        return _o1.BlockNum - _o2.BlockNum;
    }


    public boolean duplicateBlock(BlockRecord _blockRecord)
    {
        return (this.BlockID.equals(_blockRecord.BlockID) &&
                this.SignedBlockID.equals(_blockRecord.SignedSHA256) &&
                this.VerificationProcessID.equals(_blockRecord.VerificationProcessID) &&
                this.CreatingProcessID.equals(_blockRecord.CreatingProcessID) &&
                this.TimeStamp.equals(_blockRecord.TimeStamp) &&
                this.TimestampAdded.equals(_blockRecord.TimestampAdded) &&
                this.TimestampVerified.equals(_blockRecord.TimestampVerified) &&
                this.PreviousHash.equals(_blockRecord.PreviousHash) &&
                this.uuid.equals(_blockRecord.uuid) &&
                this.Data.equals(_blockRecord.Data) &&
                this.RandomSeed.equals(_blockRecord.RandomSeed) &&
                this.WinningHash.equals(_blockRecord.WinningHash) &&
                this.SHA256String.equals(_blockRecord.SHA256String) &&
                this.SignedSHA256.equals(_blockRecord.SignedSHA256));
    }
}


class DataBlock
{
    @SerializedName(value = "FirstName")
    protected String FirstName = "";
    //
    @SerializedName(value = "LastName")
    protected String LastName = "";

    @SerializedName(value = "SSN")
    protected String SSN = "";

    @SerializedName(value = "DOB")
    protected String DOB = "";

    @SerializedName(value = "Diagnosis")
    protected String Diagnosis = "";

    @SerializedName(value = "Treatment")
    protected String Treatment = "";

    @SerializedName(value = "RX")
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
}

class Ports
{
    protected static final int KeyManagementPort = 1524;
    // declare a final int representing our key management port number
    protected static int KeyServerPortBase = 6150;
    // starting port num when the process first runs for the Key Server
    protected static int UVBServerPortBase = 6250;
    // starting point num when the process fisrt runs for the Unverified Block Server
    protected static int BlockchainServerPortBase = 6350;
    // starting port num when the process first runs for Blockchain Server

    protected static int[] KeyServerPortsUsed = new int[bcE.ProcessCount];
    // new int array to store the ports being used
    protected static int[] UVBServerPortsUsed = new int[bcE.ProcessCount];
    // new int array to store the ports being used for the Unverified Block Server
    protected static int[] BlockchainServerPortsUsed = new int[bcE.ProcessCount];
    // new int array to store the ports being used for the Blockchain Server

    public static int KeyServerPort;
    // where we will hold the incremented port num for new processes running Key Server
    public static int UVBServerPort;
    // where we will hold the incremented port num for new processes running Unverified Blockchain Server
    public static int BlockchainServerPort;
    // where we will hold the incremented port num for new processes running Blockchain Server

    public static void setPortsAll(int _runningProcessCount)
    {
        for (int i = 0; i < _runningProcessCount; i++)
        {
            KeyServerPortsUsed[i] = KeyServerPortBase + i;
            //
            UVBServerPortsUsed[i] = UVBServerPortBase + i;
            //
            BlockchainServerPortsUsed[i] = BlockchainServerPortBase + i;
        }
    }

    public static void setPortsCurrent(int _processID)
    {
        KeyServerPort = KeyServerPortBase + _processID;
        //
        UVBServerPort = UVBServerPortBase + _processID;
        //
        BlockchainServerPort = BlockchainServerPortBase + _processID;
        //
    }

    public static int getKeyServerPort()
    {
        return KeyServerPort;
        // getter for retrieving the key server port number
    }

    public static int getUVBServerPort()
    {
        return UVBServerPort;
        // getter to return unverified blockchain server port number
    }

    public static int getBlockchainServerPort()
    {
        return BlockchainServerPort;
        // getter to return bloockchain server port number
    }

    public static int[] getUsedKeyServerPorts()
    {
        return KeyServerPortsUsed;
    }

    public static int[] getUsedUVBPorts()
    {
        return UVBServerPortsUsed;
    }

    public static int[] getUsedBlockchainPorts()
    {
        return BlockchainServerPortsUsed;
    }
}


class KeyManager // class to manage the creation and distribution of public and private keys
{
    private KeyPair keyPair = null;
    // declare and initialize new keypair var to null
    private PublicKey publicKey = null;
    // declare and initialize new public key variable to null
    private PrivateKey privateKey = null;
    // declare and initialize new private key to null
    private Signature signer = null;
    // declare and initialize a new Signature var signer to null

    public KeyManager(PublicKey _publicKey) {
        String signAlg = "SHA1withRSA";
        // set the signing algorithm
        try {
            this.signer = Signature.getInstance(signAlg);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            bcE.errorLog("please use the valid encryption method for the signature ", noSuchAlgorithmException);
            noSuchAlgorithmException.printStackTrace();
            // print caught exceptions to the console
        }

        this.publicKey = _publicKey;
        // bind key management constructor to incoming public key
    }

    public KeyManager() {
        String signAlg = "SHA1withRSA";
        // set the signing algorithm
        try {
            this.signer = Signature.getInstance(signAlg);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            bcE.errorLog("please use the valid encryption method for generating key ", noSuchAlgorithmException);
            noSuchAlgorithmException.printStackTrace();
            // print caught exceptions to the console
        }
    }

    public void generateKeyPair(long _seed) throws Exception {
        String encryptionAlgorithm = "RSA";
        // declare a string containing rsa alg for encryption
        String hashingAlgorithm = "SHA1PRNG";
        // declare string for sha1prng alg for hashing
        String hashAlgorithmProvider = "SUN";
        // declare string for hash algorithm provider

        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(encryptionAlgorithm);
            // initialize a new key pair generator of type RSA
            SecureRandom rng = SecureRandom.getInstance(hashingAlgorithm, hashAlgorithmProvider);
            // initialize a new secure random number generator
            rng.setSeed(_seed);
            // set our seed
            keyPairGenerator.initialize(1024, rng);
            // start generating

            this.keyPair = keyPairGenerator.generateKeyPair();
            this.publicKey = keyPair.getPublic();
            this.privateKey = keyPair.getPrivate();
            // binds the generated keys to itself
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            bcE.errorLog("Please provide valid encryption alg for generating a key pair", noSuchAlgorithmException);
            noSuchAlgorithmException.printStackTrace();
            // print out caught exceptions to the console
        }
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
        // getter to retrieve the pubkey
    }

    public void setPublicKey(PublicKey _pubKey) {
        this.publicKey = _pubKey;
        //setter for public key (this is insecure and should not be called)
    }

    public byte[] signData(byte[] _unsignedData) {
        try {
            this.signer.initSign(this.privateKey);
            // signature belonging to this process signs with private key
            this.signer.update(_unsignedData);
            // signature belonging to this process updates the unsigned data after signing
            return this.signer.sign();
            // return byte array of signed data
        } catch (SignatureException exception) {
            bcE.errorLog("Signing error...", exception);
            exception.printStackTrace();
            return null;
        } catch (InvalidKeyException exception) {
            bcE.errorLog("Invalid key...", exception);
            exception.printStackTrace();
            return null;
        }
    }

    public boolean verifySig(byte[] _unsignedData, byte[] _signedData) {
        try {
            this.signer.initVerify(this.publicKey);
            // verify signature from running process with its respective public key
            this.signer.update(_unsignedData);
            // update the unsigned data
            return this.signer.verify(_signedData);
            // return our verified signature
        } catch (SignatureException exception) {
            bcE.errorLog("Signature error...", exception);
            exception.printStackTrace();
            return false;
        } catch (InvalidKeyException exception) {
            bcE.errorLog("Invalid Key....", exception);
            exception.printStackTrace();
            return false;
        }
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
        try
        {
            BufferedReader input = new BufferedReader(new InputStreamReader(keySocket.getInputStream()));
            // declare and initialize new Buffered Reader for our input
            String data = input.readLine();
            // declare and initialize variable data to hold our input in String format
            System.out.println("Got key: " + data);
            // print out our key to the console
            keySocket.close();
            // close the keySocket off
        } catch (IOException ioe)
        {
            ioe.printStackTrace();
            // print out any exceptions caught out to console to debug
        }
    }
}

class PublicKeyServer implements Runnable
{
    public DataBlock[] PBlock = new DataBlock[3];
    // declare new array of Process Blocks to store the processes we plan to start up

    public void run()
    {
        int q_len = 6;
        Socket keySocket;
        System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
        // print out to the console which port is being used for the key server port

        try
        {
            ServerSocket serverSocket = new ServerSocket(Ports.KeyServerPort, q_len);
            // declare and initialize anew server socket
            while (true)
            {
                keySocket = serverSocket.accept();
                // keep accepting incoming connections
                new PublicKeyWorker(keySocket).start();
                // spawn our worker to begin handling those connections
            }
        } catch (IOException ioe)
        {
            bcE.errorLog("DEBUG HERE (right after starting key server input thread" , ioe);
            System.out.println(ioe);
        }
    }
}

class UVBServer implements Runnable
{
    BlockingQueue<BlockRecord> queue;
    // declare a new Clocking Queue of BlockRecords

    UVBServer(BlockingQueue<BlockRecord> queue)
    {
        this.queue = queue;
        // constructor to bind priority queue to local variable queue
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

    class UVBWorker extends Thread
    {
        Socket socket;
        // socket member variable

        UVBWorker (Socket _sock)
        {
            socket = _sock;
            // assign socket to argument _sock
        }

        BlockRecord BR = new BlockRecord();
        // declare and initialize a new BlockRecord

        public void run()
        {
            System.out.println("In Unverified Block Worker");
            // print out debugging statement to know where we are in console
            try
            {
                ObjectInputStream unverifiedInput = new ObjectInputStream(socket.getInputStream());
                // declare a new Object Input Stream and assign to variable unverifiedInput
                BR = (BlockRecord) unverifiedInput.readObject();
                // read in block record from unverified input and save it to variable BR
                System.out.println("Received Unverified Block: " + BR.getTimeStamp() + " " + BR.getData());
                // print to the console the unverified blocks timestamp and data contained
                queue.put(BR);
                // add our block record to our blocking queue
                // may fail if we do not have our queue set to be large enough to contain all puts
                socket.close();
                // close the sockets connection
            } catch (Exception exception)
            {
                exception.printStackTrace();
                // print out any exceptions caught to the console to debug
            }
        }
    }

    public void run()
    {
        int q_len = 6;
        // number of opsys requests
        Socket socket;
        // declare new socket to connect UVBServer
        System.out.println("Starting the Unverified Block Server input thread using: " + Integer.toString(Ports.UVBServerPort));
        // print to the client that we are starting up the UVBServer input thread
        try
        {
            ServerSocket UVBServerSocket = new ServerSocket(Ports.UVBServerPort);
            // declare and initialize new server socket  for our incoming unverified blocks
            while (true)
            {
                socket = UVBServerSocket.accept();
                // connect server socket to retrieve new UVB
                System.out.println("*New Connection to the Unverified Block Server*");
                // print out a notification to the client that we received a new connection to the UVBServer
                new UVBWorker(socket).start();
                // spawn new unverified block worker to handle new processes
            }
        } catch (IOException ioe)
        {
            ioe.printStackTrace();
            // notify client that an exception was caught
        }
    }
}



class BlockchainWorker extends Thread
{
    Socket socket;
    // declare a socket for our blockchain worker
    BlockchainWorker(Socket _sock)
    {
        socket = _sock;
        // assign socket to _sock in constructor
    }

        public void run()
        {
            try
            {
                BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                String blockData = "";
                // declare and initialize block data to an empty string
                String blockDataInput = input.readLine();
                // declare and initialize a block data input variable  that takes in input from our Buffered Reader
                while((blockDataInput = input.readLine()) != null)
                {
                    blockData = blockData + "\n" + blockDataInput + "\n\r\n\r";
                    // print put block data to the console
                }
                bcE.fakeBlock = blockData;
                // replace with winning blockchain
                System.out.println(" _____________New Blockchain_____________\n" + bcE.fakeBlock + "\n\n");
                socket.close();
                // close our sockdt
            } catch (IOException ioe)
            {
                ioe.printStackTrace();
            }
        }
}


class BlockchainServer implements Runnable
{
    public void run()
    {
        int q_len = 6;
        // number of opsys requests
        Socket socket;
        // declare a new socket
        System.out.println("Starting the Blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort) + "\n");
        try
        {
            ServerSocket serverSocket = new ServerSocket(Ports.BlockchainServerPort, q_len);
            // declare and implement new server socket taking in the blockchain server port
            while (true)
            {
                socket = serverSocket.accept();
                // accept incoming connections
                new BlockchainWorker(socket).start();
                // spawn new blockchain worker to handle requests
            }
        } catch (IOException ioException)
        {
            ioException.printStackTrace();
            // print out caught exceptions
        }
    }
}

class DemonstrateUtils
{
    private static KeyManager manageKeys = null;
    // declare and initialize key management var manageKeys as a private member variable of DemonstrateUtils class

    public static KeyManager getKeyManager()
    {
        return manageKeys;
        // getter to return manageKeys object
    }

    public static void setManageKeys(KeyManager _manageKeys)
    {
        manageKeys = _manageKeys;
        // set by setting manageKeys variable to new _manageKeys
    }

    public static ArrayList<BlockRecord> ReadInputFile(String _fileName, int _processID) {
        ArrayList<BlockRecord> blockRecordArrayList = new ArrayList<BlockRecord>();
        // declare and inititalize new ArrayList that contains BlockRecords
        String currentPID = Integer.toString(_processID);
        // save our process id from argument in string format
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(_fileName))) {
            String input;
            // declare new input string to read in lines
            while ((input = bufferedReader.readLine()) != null) {
                BlockRecord blockRecord = new BlockRecord();
                // declare and initialize new BlockRecord object
                blockRecord.setBlockID(new String(UUID.randomUUID().toString()));
                // set the block ID with a new random uuid
                blockRecord.setCreatingProcessID(currentPID);
                // set the PID for the current process
                String[] inputArray = input.split(" +");
                // tokenize our input line by splitting into an array and setting by index position
                blockRecord.getDataBlock().setFirstName(inputArray[0]);
                blockRecord.getDataBlock().setLastName(inputArray[1]);
                blockRecord.getDataBlock().setDOB(inputArray[2]);
                blockRecord.getDataBlock().setSSN(inputArray[3]);
                blockRecord.getDataBlock().setDiag(inputArray[4]);
                blockRecord.getDataBlock().setTreat(inputArray[5]);
                blockRecord.getDataBlock().setRX(inputArray[6]);

                blockRecordArrayList.add(blockRecord);
            }
        } catch (Exception exception) {
            bcE.errorLog("Error readign input file..." , exception);
            exception.printStackTrace();
            System.out.println();
        }

        System.out.println(blockRecordArrayList.size() + " records read.");
        // print out to the console how many records have been read
        System.out.println("Names from input: " );
        // Print out the header for the patient names we are about to print
        for (BlockRecord blockRecord: blockRecordArrayList)
        {
            System.out.println("\t" + blockRecord.getDataBlock().getFirstName() + " " + blockRecord.getDataBlock().getLastName());
        }
        System.out.println("\n");
        // print to the console to help with formatting
        return blockRecordArrayList;
    }

    public static String SerializeBlockRecord(ArrayList<BlockRecord> _blockRecords) throws Exception // for serailizing multiple records
    {
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        // declare and initialize a new google gson object to build our JSON string
        return gson.toJson(_blockRecords);
        // return our new JSON string
    }

    public static String SerializeDataBlock(DataBlock _dataBlock)
    {
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        // declare and initialize a new google gson object to build our JSON string
        return gson.toJson(_dataBlock);
        // return our new JSON string
    }

    public static String SerializeBlockRecord(BlockRecord _blockRecord) // for a single record
    {
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        // declare and initialize a new google gson object to build our JSON string
        return gson.toJson(_blockRecord);
        // return our new JSON string
    }

    public static BlockRecord DeserializeBlockRecord(String _blockRecord)
    {
        return new Gson().fromJson(_blockRecord, BlockRecord.class);
        // deserialize by building a new gson fromJson using our arg string and the BlockRecord runnable
    }

    public static ArrayList<BlockRecord> DeserializeBlockchainLedger(String _ledger)
    {
        Type tokenList = new TypeToken<ArrayList<BlockRecord>>(){}.getType();
        // declare and initialize a new variable of class Type to help tokenize our ledger of blockchain records
        return new Gson().fromJson(_ledger, tokenList);
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
                bcE.errorLog("Error sending Unverified Block...", exception);
                exception.printStackTrace();
                System.out.println();
            } finally {
                output.close();
                UnverifiedBlockSocket.close();
                // close our socket and print stream
            }
        } catch (Exception exception) {
            bcE.errorLog("Error! Could not send Unverified Block...", exception);
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
                toServer.writeObject("(FakeKeyProcess) Sendiong public keys: " + manageKeys.getPublicKey() + "\n");
                // print out fake key process/ well real key process now
                toServer.flush();
                // flush the object output stream
                socket.close();
                // close off socket connections
            } catch (Exception exception) {
                bcE.errorLog("Connection Exception\nCould not send keys: " + i, exception);
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


    public static String mineBlock(int _prefix)
    {
        String prefixString = new String(new char[_prefix]).replace('\0', '0');
        /*
         * declare and intialialize our prefix string to a new string containing our prefix integer with '\0' replaced
         * by '0' to represent the prefix we are looking for
         */

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

    public static void doWork(String a[]) throws Exception
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

class UVBConsumer implements Runnable
{
    public void run()
    {
        BlockRecord blockRecord;

        System.out.println("Now in Unverified Block Consumer");

        try {
            while(true)
            {
                boolean hasBlock = false;
                // declare a new bool adn set to false for if there is a block
                blockRecord = bcE.BlockchainPriorityQueue.take();
                // take a block from our priority queue and save it in our block record object
                System.out.println("Unverified Blockchain Consumer received a new UVB: " + DemonstrateUtils.SerializeBlockRecord(blockRecord));
                // print out that a new unverified block was received by UVB consumer and serialize said block
                for (BlockRecord ledger: bcE.BlockLedger)
                {
                    if (ledger.getBlockID().compareToIgnoreCase(blockRecord.getBlockID()) == 0){
                        hasBlock = true;
                        break;
                    }
                }
                if (!validBlock(blockRecord))
                {
                    continue;
                }
                try {
                    int currentBlockNum = bcE.BlockLedger.size() + 1;
                    // set the current blocks number in the next available index of the ledger
                    blockRecord.setBlockNum(currentBlockNum);
                    // set the block num in the block record object
                    blockRecord.setVerificationProcessID(Integer.toString(bcE.ProcessID));
                    // set the verification process id to the current process ID
                    String previousHash;
                    // declare previous hash variable
                    if (!blockRecord.getBlockID().equals("0") && bcE.BlockLedger.size() != 0)
                    {
                        int previousBlockNumber = bcE.BlockLedger.size() - 1;
                        // set the previous blocks number to the last index
                        previousHash = bcE.BlockLEdger.get(previousBlockNumber).getPreviousHash();
                    } else {
                        previousHash = DatatypeConverter.printHexBinary(DemonstrateUtils.getHashByteArray(blockRecord.getHashedBlock()));
                        // turn the hash byte array into a string and set it as previous hash
                    }
                    for (int i = o; i < 700; i++)
                    {
                        String randSeed = this.randomAlphaNumeric(10);
                        // new random string
                        String concatenatedString = previousHash + randomSeed;
                        // concatenate random sring with the previosu hash and save it concatenateString variable
                        String newHash = DatatypeConverter.printHexBinary(DemonstrateUtils.getHashByteArray(concatenatedString));
                        // convert our concatenated string into byte array and then then to a string to save in new hash variable
                        if (this.isWinningHash(newHash))
                        {
                            blockRecord.setRandomSeed(randSeed);
                            // set the random seed to reflect that the work was competed for and solved
                            blockRecord.setPreviousHash(concatenatedString);
                            // set the previous blocks hash
                            break;
                            // quit out once we have the hashes set in block record object
                        }

                        for (BlockRecord ledger: bcE.BlockLedger)
                        {
                            if (ledger.getBlockID().compareToIgnoreCase(blockRecord.getBlockID()) == 0)
                            {
                                System.out.println("This Block has already been verified...\nWaiting for new Block");
                                hasBlock = true;
                                break;
                            }
                        }
                        if (hasBlock)
                        {
                            break;
                            // exit out if hasBlock is already true
                        }
                    }
                } catch (Exception exception)
                {
                    bcE.errorLog("Error when performing work....", exception);
                    exception.printStackTrace();
                    System.out.println();
                }
                if (!hasBlock)
                {
                    for (BlockRecord ledger: bcE.BlockLedger)
                    {
                        if (ledger.getBlockID().compareToIgnoreCase(blockRecord.getBlockID()) == 0)
                        {
                            System.out.println("((2)) Block already verified... Waiting");
                            hasBlock = true;
                            break;
                        }
                    }
                    if (!hasBlock) // if a process did not solve yet just add the record and count it as verified
                    {
                        bcE.BlockLedger.add(blockRecord);
                        this.SendVerified();
                    }
                }
            }
        } catch (Exception exception)
        {
            bcE.errorLog("Exception caught when attempting to verify Block...", exception);
            exception.printStackTrace();
            System.out.println();
        }
    }

    private boolean isWinningHash(String _winningHash) throws Exception
    {

    }
}


public class bcE
{
    public static String hash;
    public static final int processID = 0;
    public static int PID = 0;
    public static String previousHash;
    public static String data;
    public static long timeStamp;
    public static String TimeStamp;
    public static int  nonce;
    // declaration of private member variables for block header

    public static String serverName = "localhost";
    // declare our servername and save it as a string

    public static String fakeBlock = "[first block]";
    // declare our dummy genesis block

    public static int numProcesses = 3;
    // number of processes we plan to run

    //public static int PID = 0;
    // ID numberof this process

    public static final String ALGORITHM = "RSA";
    // using RSA encryption

    public static LinkedList<BlockRecord> recordList = new LinkedList<BlockRecord>();
    // declare and initialize a new linked list full of BlockRecords

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

    public static final PriorityBlockingQueue<BlockRecord> BlockchainPriorityQueue = new PriorityBlockingQueue<BlockRecord>(100, BlockTimeStampComparator);
    // declare a final blocking priority queue that is concurrent


    /*
     * public constructor for Blockchain_C
     * @param data var of type String
     * @param previousHash var of type String
     * @param timeStamp variable of type long
     */
    public bcE(String data, String previousHash, long timeStamp)
    {
        this.data = data;
        this.previousHash = previousHash;
        this.timeStamp = timeStamp;
        // getters and setters
        this.hash = calculateBlockHash();
        // assigns hash to itself
    }


    public static String calculateBlockHash()
    // method to calculate hash for current block
    {
        String dataToHash = previousHash + Long.toString(timeStamp) + Integer.toString(nonce) + data;
        // concatenation of hash of the previous tx ,time of tx, the tx nonce, ans the tx data
        MessageDigest digest = null;
        // declare new message digest objecgt and isntatntiate to null
        byte[] bytes = null;
        // declare and initialize a new byte array

        try
        {
            digest = MessageDigest.getInstance("SHA-256");
            // get an instance of the SHA256 hashing algorithm and store it in digest
            bytes = digest.digest(dataToHash.getBytes("UTF-8"));
            // generate the hash value of our input data and stick in in our new byte array
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException exception)
        {
            System.err.println("Exception found: " + exception);
            exception.printStackTrace();
            // print exceptions to console
        }

        StringBuffer buffer = new StringBuffer();
        // declare and initialize anew string buffer
        for (byte b: bytes)
        // cycle through all bytes in bytes
        {
            buffer.append(String.format("%02x", b));
            // turn said byte into a hex string
        }
        return buffer.toString();
        // return our string buffer that now holds our hash
    }


    /*
     * method for mining a new block
     * @param a prefix var of type integer
     *
     * please note that this implementation does not verifying any date which
     * is a crucial component of blockchains with real-world application
     */

    public String getHash()
    {
        return DemonstrateUtils.getHash();
    }

    public String getPreviousHash()
    {
        return previousHash;
        // getter to return previous hash
    }

    public String getData()
    {
        return data;
    }

    public static void sendData(String data)
    {
        bcE.data = data;
        // method to send data to the block
    }

    public static String getTimeStamp()
    {
        return TimeStamp;
    }

    public void setTimeStamp(String _timeStamp)
    {
        this.TimeStamp = _timeStamp;
    }


    public static void errorLog(String _errorString, Exception _exception)
    {
        String errorLogHeader = "___!!!!!!!!!!_ERROR_!!!!!!!!!!___\n";
        // create a header for our error log, this should be much more efficient than just printing out stack traces everywhere
        errorLogHeader += "Process number " + bcE.processID + ": " + _errorString + " has caught exception: " + _exception + "\n";
        // concatenate our string with required fileds to report caught errors
        System.out.println(errorLogHeader);
        // print out our error log entry to the console
    }

    public static void main(String a[])
    {
        String inputFile;

        if (a.length == 0)
        {
            System.out.println("\nWelcome\nBlockchain Process: " + bcE.PID + " running without command argument\n");
        }
        else
        {
            PID = Integer.parseInt(a[0]);
        }

        switch (PID)
        {
            case 1:
            {
                inputFile = "BlockInput1.txt";
                System.out.println("Hello from process " + PID);
                break;
            }
            case 2:
            {
                inputFile = "BlockInput2.txt";
                System.out.println("Hello from process " + PID);
                break;
            }
            default :
            {
                inputFile = "BlockInput0.txt";
                System.out.println("Hello from process " + PID);
                break;
            }
        }

        Ports.setPorts();
        System.out.println("Public Key Port numbers: " + Ports.getKeyServerPort());
        System.out.println("Unverified Blockchain Port number: " + Ports.getUVBServerPort())  ;
        System.out.println("Blockchain Port number: " + Ports.getBlockchainServerPort());


        try
        {
            new Thread(new PublicKeyServer()).start();
            // initiate a new thread for processing publick keys
            new Thread(new UVBServer(BlockchainPriorityQueue)).start();
            // start an new thread to process unverified blocks
            new Thread(new BlockchainServer()).start();
            // start a new thread for incoming blocks
            try
            {
                Thread.sleep(1000);
            } catch (Exception exception)
            {
                exception.printStackTrace();
            }
            DemonstrateUtils.KeySend();
            try
            {
                Thread.sleep(1000);
            } catch (Exception exception)
            {
                exception.printStackTrace();
            }
            Thread.sleep(1000);
        } catch (Exception exception)
        {
            exception.printStackTrace();
        }

        try
        {
            System.out.println("Hello from Process: " + bcE.PID + "\nWaiting for a Public Key: " + bcE.getTimeStamp());
            new DemonstrateUtils().UnverifiedSend();
            Thread.sleep(1000);
        } catch (Exception exception)
        {
            exception.printStackTrace();
        }

        try
        {
            new Thread(new UVBConsumer(BlockchainPriorityQueue)).start();
        } catch ( Exception exception)
        {
            exception.printStackTrace();
        }


        /*
            below is what is necessary for implementing Elliott's requirements:
                demonstrateUtil checks the command line argument for the process ID and assigns the blochain
                a port number depending on the process ID and if the blockchain is verified or unverified

                writeToJSOn does exactly that

                readFromJSON does exactly that


        try
        {
            DemonstrateUtils.demonstrateUtils(a);
        } catch (Exception e)
        {
            e.printStackTrace();
        }



        DemonstrateUtils.writeToJSON();
        // write our output to JSON file
        DemonstrateUtils.readFromJSON();
        // read our input from a JSON file

        System.out.println("Running now\n");
        // print to the console that main is running
        //int q_len = 6;
        // num of opsys requests
        PID = (a.length < 1) ? 0 : Integer.parseInt(a[0]);
        // to determine process ID
        System.out.println("Bryce Jensen's Block Coordinating Framework for Clark Elliott's CSC435 . Stop process with ctrl+c");
        // inform the console what is runing
        System.out.println("Using process ID: " + PID + "\n");
        // print out the process number coming through
        new Ports().setPorts();
        // determine port number depending on process id

        new Thread(new PublicKeyServer()).start();
        // initiate a new thread for processing publick keys
        new Thread(new UVBServer(BlockchainPriorityQueue)).start();
        // start an new thread to process unverified blocks
        new Thread(new BlockchainServer()).start();
        // start a new thread for incoming blocks
        try
        {
            Thread.sleep(1000);
            // give servers some time to work
        } catch (Exception exception)
        {
            exception.printStackTrace();
            // print any caught exceptionsto the console
        }

        DemonstrateUtils.KeySend();
        // send the keys


         */

    }
}





