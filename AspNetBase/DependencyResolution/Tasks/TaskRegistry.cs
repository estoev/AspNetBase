using StructureMap.Configuration.DSL;
using StructureMap.Graph;

namespace AspNetBase.DependencyResolution.Tasks
{
    public class TaskRegistry : Registry
    {
        public TaskRegistry()
        {
            Scan(scan =>
                 {
                     scan.AssembliesFromApplicationBaseDirectory(
                         a => a.FullName.StartsWith("AspNetBase"));
                     scan.AddAllTypesOf<IRunAtStartup>();
                     scan.AddAllTypesOf<IRunOnEachRequest>();
                     scan.AddAllTypesOf<IRunOnError>();
                     scan.AddAllTypesOf<IRunAfterEachRequest>();
                 });
        }
    }

    public interface IRunAfterEachRequest
    {
        void Execute();
    }

    public interface IRunAtStartup
    {
        void Execute();
    }

    public interface IRunOnEachRequest
    {
        void Execute();
    }

    public interface IRunOnError
    {
        void Execute();
    }
}