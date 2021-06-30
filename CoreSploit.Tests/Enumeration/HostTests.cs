using System.Diagnostics;
using Xunit;

namespace CoreSploit.Tests.Enumeration
{
    public class HostTests
    {
        [Fact]
        public void GetProcessList()
        {
            var result = CoreSploit.Enumeration.Host.GetProcessList();
            
            Debug.WriteLine(result.ToString());
            
            Assert.NotNull(result);
            Assert.NotEmpty(result);
        }
    }
}