using System.Runtime.InteropServices;
using System.Runtime.Versioning;

namespace Compliance.Agent;

/// <summary>
/// The full names of a user's Store (Appx/MSIX) packages from the Windows Runtime <c>PackageManager</c>, the API behind
/// <c>Get-AppxPackage -User</c>. It is called through its binary interface instead of the Windows SDK projection, which
/// would add 25 MB to the client package. Only FindPackagesForUser(sid) → IIterable&lt;Package&gt; → IPackage.Id.FullName
/// is declared; the interface ID and method slots are those in the Windows SDK metadata
/// (Windows.Foundation.UniversalApiContract.winmd and Windows.Foundation.FoundationContract.winmd).
/// </summary>
[SupportedOSPlatform("windows")]
internal static unsafe class StorePackages
{
    private const string PackageManagerClass = "Windows.Management.Deployment.PackageManager";
    private static readonly Guid IPackageManager = new("9a7d4b65-5e8f-4fc7-a2e5-7f6925cb8b53");

    // Method slots counted from 0, after IUnknown's three and IInspectable's three methods.
    private const int FindPackagesForUserSlot = 12; // IPackageManager.FindPackagesForUser(userSecurityId)
    private const int FirstSlot = 6; // IIterable<Package>.First
    private const int CurrentSlot = 6; // IIterator<Package>.Current
    private const int HasCurrentSlot = 7; // IIterator<Package>.HasCurrent
    private const int MoveNextSlot = 8; // IIterator<Package>.MoveNext
    private const int IdSlot = 6; // IPackage.Id
    private const int FullNameSlot = 12; // IPackageId.FullName

    public static string[] ForUser(string sid)
    {
        // The collectors run on thread-pool threads, which are in the multithreaded apartment.
        var initialized = RoInitialize(RO_INIT_MULTITHREADED) >= 0;
        nint inspectable = 0,
            manager = 0,
            iterable = 0,
            iterator = 0;
        try
        {
            using (var name = new HString(PackageManagerClass))
                Check(RoActivateInstance(name.Handle, out inspectable));
            var iid = IPackageManager;
            Check(Marshal.QueryInterface(inspectable, in iid, out manager));
            using (var user = new HString(sid))
                Check(
                    ((delegate* unmanaged[Stdcall]<nint, nint, nint*, int>)Slot(manager, FindPackagesForUserSlot))(
                        manager,
                        user.Handle,
                        &iterable
                    )
                );
            Check(((delegate* unmanaged[Stdcall]<nint, nint*, int>)Slot(iterable, FirstSlot))(iterable, &iterator));
            var names = new List<string>();
            byte more;
            Check(((delegate* unmanaged[Stdcall]<nint, byte*, int>)Slot(iterator, HasCurrentSlot))(iterator, &more));
            while (more != 0)
            {
                names.Add(FullName(iterator));
                Check(((delegate* unmanaged[Stdcall]<nint, byte*, int>)Slot(iterator, MoveNextSlot))(iterator, &more));
            }
            return names.ToArray();
        }
        finally
        {
            Release(iterator);
            Release(iterable);
            Release(manager);
            Release(inspectable);
            if (initialized)
                RoUninitialize();
        }
    }

    private static string FullName(nint iterator)
    {
        nint package = 0,
            id = 0,
            name = 0;
        try
        {
            Check(((delegate* unmanaged[Stdcall]<nint, nint*, int>)Slot(iterator, CurrentSlot))(iterator, &package));
            Check(((delegate* unmanaged[Stdcall]<nint, nint*, int>)Slot(package, IdSlot))(package, &id));
            Check(((delegate* unmanaged[Stdcall]<nint, nint*, int>)Slot(id, FullNameSlot))(id, &name));
            uint length;
            var buffer = WindowsGetStringRawBuffer(name, &length);
            return new string(buffer, 0, (int)length);
        }
        finally
        {
            if (name != 0)
                WindowsDeleteString(name);
            Release(id);
            Release(package);
        }
    }

    private static void* Slot(nint instance, int index) => (*(void***)instance)[index];

    private static void Check(int hr) => Marshal.ThrowExceptionForHR(hr);

    private static void Release(nint instance)
    {
        if (instance != 0)
            Marshal.Release(instance);
    }

    /// <summary>A Windows Runtime string, deleted when disposed.</summary>
    private readonly struct HString : IDisposable
    {
        public readonly nint Handle;

        public HString(string value) => Check(WindowsCreateString(value, (uint)value.Length, out Handle));

        public void Dispose() => WindowsDeleteString(Handle);
    }

    private const int RO_INIT_MULTITHREADED = 1;

    [DllImport("combase.dll")]
    private static extern int RoInitialize(int type);

    [DllImport("combase.dll")]
    private static extern void RoUninitialize();

    [DllImport("combase.dll")]
    private static extern int RoActivateInstance(nint activatableClassId, out nint instance);

    [DllImport("combase.dll", CharSet = CharSet.Unicode)]
    private static extern int WindowsCreateString(string source, uint length, out nint value);

    [DllImport("combase.dll")]
    private static extern int WindowsDeleteString(nint value);

    [DllImport("combase.dll")]
    private static extern char* WindowsGetStringRawBuffer(nint value, uint* length);
}
