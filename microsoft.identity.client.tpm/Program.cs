using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace microsoft.identity.client.tpm
{

    internal class Program
    {
        private static IntPtr hTbsContext_ = new IntPtr();

        // Define the TBSI constants
        private const int TBS_SUCCESS = 0;

        // Define the TBS device type constant
        private const uint TBS_DEVICE_TYPE = 0x00000001;

        // Define the TBS property constants
        private const uint TBS_PROPERTY_VERSION = 1;
        private const uint TBS_PROPERTY_MANUFACTURER = 2;
        private const uint TBS_PROPERTY_VENDOR_ID = 3;
        private const uint TBS_PROPERTY_FIRMWARE_VERSION = 4;

        /// <summary>
        /// TBS_CONTEXT_PARAMS structure
        /// Specifies the version of the TBS context implementation.
        /// To connect to TBS, the client must run as administrator. 
        /// TBS also limits access to locality ZERO.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]

        private struct TBS_CONTEXT_PARAMS
        {
            /// <summary>
            /// The version of the TBS context implementation. This parameter must be TBS_CONTEXT_VERSION_ONE.
            /// </summary>
            public UInt32 version;
        };

        /// <summary>
        /// Provides information about the version of the TPM.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct TBS_DEVICE_INFO
        {
            public UInt32 TpmVersion;
            public UInt32 TpmInterfaceType;
            public UInt32 TpmDeviceId;
            public UInt32 TpmManufacturer;
            public UInt32 TpmFirmwareVersion;
            public UInt32 TpmVendorSpecificSize;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public byte[] TpmVendorSpecific;
        }

        /// <summary>
        /// Creates a context handle that can be used to pass commands to TBS.
        /// </summary>        
        /// <param name="pContextParams">A parameter to a TBS_CONTEXT_PARAMS structure that contains the parameters associated with the context.</param>
        /// <param name="phContext">A pointer to a location to store the new context handle.</param>
        /// <returns>If the function succeeds, the function returns TBS_SUCCESS. 0 (0x0)</returns>
        [DllImport("tbs.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern UInt32 Tbsi_Context_Create(
             ref TBS_CONTEXT_PARAMS pContextParams,
             out IntPtr phContext
        );

        /// <summary>
        /// Submits a Trusted Platform Module (TPM) command to TPM Base Services (TBS) for processing.
        /// </summary>
        /// <param name="hContext">The handle of the context that is submitting the command. Handle acquired using Tbsi_Context_Create.</param>
        /// <param name="locality">Used to set the locality for the TPM command. TBS_COMMAND_LOCALITY_ZERO - 0 (0x0) is the only supported locality.</param>
        /// <param name="priority">The priority level that the command should have.</param>
        /// <param name="cmdBuf">A pointer to a buffer that contains the TPM command to process.</param>
        /// <param name="cmdBufLen"></param>
        /// <param name="respBuf"></param>
        /// <param name="respBufLen"></param>
        /// <returns></returns>
        [DllImport("tbs.dll")]
        static extern uint Tbsip_Submit_Command(IntPtr hContext, 
            uint locality,
            uint priority, 
            byte[] cmdBuf, 
            int cmdBufLen, 
            byte[] respBuf, 
            ref int respBufLen);

        public enum TBS_RESULT : uint
        {
            TBS_SUCCESS = 0,
            TBS_E_BAD_PARAMETER = 0x80284001,
            TBS_E_INTERNAL_ERROR = 0x80284002,
            TBS_E_INVALID_OUTPUT_POINTER = 0x80284003,
            TBS_E_INVALID_CONTEXT = 0x80284004,
            TBS_E_INSUFFICIENT_BUFFER = 0x80284005,
            TBS_E_IOERROR = 0x80284006,
            TBS_E_INVALID_CONTEXT_PARAM = 0x80284007,
            TBS_E_SERVICE_NOT_RUNNING = 0x80284008,
            TBS_E_TOO_MANY_TBS_CONTEXTS = 0x80284009,
            TBS_E_TOO_MANY_RESOURCES = 0x8028400A,
            TBS_E_SERVICE_START_PENDING = 0x8028400B,
            TBS_E_PPI_NOT_SUPPORTED = 0x8028400C,
            TBS_E_COMMAND_CANCELED = 0x8028400D,
            TBS_E_BUFFER_TOO_LARGE = 0x8028400E,
            TBS_E_TPM_UNAVAILABLE = 0x8028400F,
            TBS_E_UNSUPPORTED_TPM_VERSION = 0x80284010,
            TBS_E_TPM_ALREADY_IN_JOINED_MODE = 0x80284011,
            TBS_E_INVALID_RESOURCE = 0x80284012,
            TBS_E_NOTHING_TO_UNLOAD = 0x80284013,
            TBS_E_HASH_INVALID_ALG = 0x80284014,
            TBS_E_INVALID_HANDLE = 0x80284015,
            TBS_E_TPM_SECURITY_VALUES_MISSING = 0x80284016,
            TBS_E_INVALID_PCR_INDEX = 0x80284017,
            TBS_E_TPM_CONNECTION_BROKEN = 0x80284018,
            TBS_E_INVALID_ATTESTATION = 0x80284019,
            TBS_E_CRYPTO_ERROR = 0x8028401A,
            TBS_E_NO_EVENT_LOG = 0x8028401B,
            TBS_E_EVENT_LOG_FILE_FULL = 0x8028401C,
            TBS_E_EVENT_LOG_CLEARED = 0x8028401D,
            TBS_E_TPM_INCOMPATIBLE = 0x8028401E,
            TBS_E_NO_MORE_DATA = 0x8028401F,
            TBS_E_INVALID_CONTEXT_SIZE = 0x80284020,
            TBS_E_INSUFFICIENT_TPM_RESOURCES = 0x80284021,
            TBS_E_INVALID_PCR_DATA = 0x80284022,
            TBS_E_INVALID_OWNER_AUTH = 0x80284023,
            TBS_E_TOO_MANY_CONTEXT_IDS = 0x80284024,
            TBS_E_INVALID_CAPABILITY = 0x80284025,
            TBS_E_INVALID_TPM_PROPERTY = 0x80284026,
            TBS_E_PPI_FUNCTION_UNSUPPORTED = 0x80284027,
            TBS_E_PPI_BLOCKED_ON_CPL = 0x80284028,
            TBS_E_PCP_INVALID_PARAMETER = 0x90310001,
            TBS_E_PCP_ENCODE_ERROR = 0x90310002 
        }

        /// <summary>
        /// Closes a context handle, which releases resources associated with the context in TBS 
        /// and closes the binding handle used to communicate with TBS.
        /// </summary>        
        [DllImport("tbs.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern UInt32 Tbsip_Context_Close(IntPtr hContext);

        /// <summary>
        /// Obtains the version of the TPM on the computer.
        /// </summary>
        /// <param name="contextPtr"></param>
        /// <param name="deviceIndex"></param>
        /// <param name="deviceInfo"></param>
        /// <param name="deviceInfoLen"></param>
        /// <returns></returns>
        [DllImport("tbs.dll", CallingConvention = CallingConvention.Winapi)]
        public static extern uint Tbsi_Device_GetInfo(
        IntPtr contextPtr,
        uint deviceIndex,
        [MarshalAs(UnmanagedType.LPArray)] byte[] deviceInfo,
        ref uint deviceInfoLen);

        /// <summary>
        /// Main program for the TBS
        /// </summary>
        /// <param name="args"></param>
        /// <exception cref="Exception"></exception>
        static void Main(string[] args)
        {
            //Get the payload 
            var key = CreateThePayLoad();

            byte[] publicKeyBlob = key.Export(CngKeyBlobFormat.GenericPublicBlob); // Export the public key
            //byte[] privateKeyBlob = key.Export(CngKeyBlobFormat.GenericPrivateBlob); // Export the private key

            //TBS Context 
            TBS_CONTEXT_PARAMS ctx_params;
            ctx_params.version = TBS_PROPERTY_VERSION; //the only working version

            uint result = Tbsi_Context_Create(ref ctx_params, out hTbsContext_);

            if (result != TBS_SUCCESS)
            {
                Console.WriteLine(result);
                throw new Exception("Error creating TPM context");
            }

            // build the command buffer to seal the data
            byte[] cmdBuf = new byte[12 + publicKeyBlob.Length];
            cmdBuf[0] = 0x00; // TPM_ST_NO_SESSIONS
            cmdBuf[1] = 0x00; // TPM_RH_NULL
            cmdBuf[2] = 0x01; // TPM_CC_CREATE
            cmdBuf[3] = 0x00;
            cmdBuf[4] = 0x00;
            cmdBuf[5] = 0x00;
            cmdBuf[6] = (byte)((publicKeyBlob.Length >> 8) & 0xFF);
            cmdBuf[7] = (byte)(publicKeyBlob.Length & 0xFF);
            Array.Copy(publicKeyBlob, 0, cmdBuf, 12, publicKeyBlob.Length);

            // submit the command buffer to the TPM and get the response
            byte[] respBuf = new byte[4096];
            int respBufLen = respBuf.Length;

            result = Tbsip_Submit_Command(hTbsContext_, 0, 0, cmdBuf, cmdBuf.Length, respBuf, ref respBufLen);

            if (result != TBS_SUCCESS)
            {
                Console.WriteLine($"Tbsip_Submit_Command failed with error code {result}");
                return;
            }

            // extract the sealed data from the response buffer
            byte[] sealedData = new byte[respBufLen];
            Array.Copy(respBuf, 10, sealedData, 0, respBufLen - 10);

            Console.WriteLine($"Sealed data size: {sealedData.Length} bytes");
            Console.WriteLine($"Sealed data : {sealedData}");

            Tbsip_Context_Close(hTbsContext_);
            Marshal.FreeHGlobal(hTbsContext_);

            Console.Read();
        }

        private static CngKey CreateThePayLoad()
        {
            //Create the Payload 
            CngKey key = CngKey.Create(CngAlgorithm.Rsa); // Create a new RSA key

            return key;
        }
    }
}
