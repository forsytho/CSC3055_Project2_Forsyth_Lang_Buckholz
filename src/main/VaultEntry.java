public abstract class VaultEntry {

    protected String iv;      
    protected String service; // service name 

    public VaultEntry(String iv, String service) {
        this.iv = iv;
        this.service = service;
    }

    public String getIv() { return iv; }
    public String getService() { return service; }
    
}
