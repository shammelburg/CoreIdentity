using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CoreIdentity.Azure.Storage.Interfaces
{
    public interface IBlobStorage
    {
        Task<string> UploadBlob(IFormFile file, string blobRef);
        Task<string> MoveBlob(string blobRef, string newBlobRef);
        Task<bool> DeleteBlob(string blobRef);
        Task<string> GetFilesByRef(string blobRef);
    }
}
