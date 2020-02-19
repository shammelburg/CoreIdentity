using Azure.Storage.Queues;
using CoreIdentity.Azure.Storage.Interfaces;
using System;
using System.Text;
using System.Threading.Tasks;

namespace CoreIdentity.Azure.Storage.Services
{
    public class QueueStorage : IQueueStorage
    {
        private string _AzureStorageConnectionString;

        public QueueStorage(string AzureStorageConnectionString)
        {
            _AzureStorageConnectionString = AzureStorageConnectionString;
        }

        private async Task<QueueClient> GetQueueClient(string QueueName)
        {
            QueueClient queue = new QueueClient(_AzureStorageConnectionString, QueueName);

            await queue.CreateAsync();

            return queue;
        }

        public async Task<bool> SendMessage(string QueueName, string Message)
        {
            QueueClient queue = await GetQueueClient(QueueName);

            var plainTextBytes = Encoding.UTF8.GetBytes(Message);

            await queue.SendMessageAsync(Convert.ToBase64String(plainTextBytes));

            return true;
        }
    }
}
