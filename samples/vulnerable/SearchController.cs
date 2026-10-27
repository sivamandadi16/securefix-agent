// Minimal stand-in for a web controller action that writes a response.
namespace DemoApp.Web;

public class SearchController
{
    public void ShowResult(IResponse response, string searchTerm)
    {
        // 'Response' stands in for the framework response object.
        Response.Write(searchTerm);
    }

    public interface IResponse
    {
        void Write(string text);
    }

    private static IResponse Response => throw new NotImplementedException();
}
