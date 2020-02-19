using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using CoreIdentity.Azure.Storage.Interfaces;
using Microsoft.AspNetCore.Http;
using System.IO;
using System.Threading.Tasks;

namespace CoreIdentity.Azure.Storage.Services
{
    public class BlobStorage : IBlobStorage
    {
        private string _AzureStorageConnectionString;
        private string _AzureStorageContainerName;
        private string _AzureStorageUrl;

        public BlobStorage(string AzureStorageConnectionString, string AzureStorageContainerName, string AzureStorageUrl)
        {
            _AzureStorageConnectionString = AzureStorageConnectionString;
            _AzureStorageContainerName = AzureStorageContainerName;
            _AzureStorageUrl = AzureStorageUrl;
        }

        private async Task<BlobContainerClient> GetBlobContainerClient()
        {
            BlobContainerClient container = new BlobContainerClient(_AzureStorageConnectionString, _AzureStorageContainerName);

            await container.CreateIfNotExistsAsync();
            await container.SetAccessPolicyAsync(PublicAccessType.Blob);

            return container;
        }

        public async Task<string> UploadBlob(IFormFile file, string blobRef)
        {
            BlobContainerClient container = await GetBlobContainerClient();
            BlobClient blob = container.GetBlobClient(blobRef);

            using (var stream = new MemoryStream())
            {
                await file.CopyToAsync(stream);

                // reset position of the stream to 0
                stream.Seek(0, SeekOrigin.Begin);

                await blob.UploadAsync(stream);
            }

            return $"{_AzureStorageUrl}{_AzureStorageContainerName}/{blobRef}";
        }

        public async Task<string> MoveBlob(string blobRef, string newBlobRef)
        {
            BlobContainerClient container = await GetBlobContainerClient();
            BlobClient blob = container.GetBlobClient(blobRef);
            BlobClient newblob = container.GetBlobClient(newBlobRef);

            if (await blob.ExistsAsync())
            {
                await newblob.StartCopyFromUriAsync(blob.Uri);
                await blob.DeleteIfExistsAsync();
            }

            return $"{_AzureStorageUrl}{_AzureStorageContainerName}/{newBlobRef}";
        }

        public async Task<bool> DeleteBlob(string blobRef)
        {
            BlobContainerClient container = await GetBlobContainerClient();
            BlobClient blob = container.GetBlobClient(blobRef);

            return await blob.DeleteIfExistsAsync();
        }

        public async Task<string> GetFilesByRef(string blobRef)
        {
            BlobContainerClient container = await GetBlobContainerClient();
            BlobClient blob = container.GetBlobClient(blobRef);

            var path = Path.GetTempPath() + Path.GetRandomFileName();
            await blob.DownloadToAsync(path);

            return path;
        }
    }
}
