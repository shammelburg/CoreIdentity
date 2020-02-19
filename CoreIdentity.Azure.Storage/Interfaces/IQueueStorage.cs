using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace CoreIdentity.Azure.Storage.Interfaces
{
    public interface IQueueStorage
    {
        Task<bool> SendMessage(string QueueName, string Message);
    }
}
