package com.wct.otsec;

import java.net.InetAddress;
import java.util.Arrays;

/** Literal-only addresses: never resolve operator input through DNS. */
record Scope(byte[] network, int prefix) {
    static byte[] address(String value) {
        try {
            if (value.contains(":")) {
                if (!value.matches("[0-9a-fA-F:]+") || !value.contains("::") && value.chars().filter(c -> c == ':').count() != 7) throw new IllegalArgumentException();
                byte[] bytes = InetAddress.getByName(value).getAddress();
                if (bytes.length != 16) throw new IllegalArgumentException();
                return bytes;
            }
            String[] parts = value.split("\\.", -1);
            if (parts.length != 4) throw new IllegalArgumentException();
            byte[] bytes = new byte[4];
            for (int i=0;i<4;i++) {
                if (!parts[i].matches("0|[1-9][0-9]{0,2}")) throw new IllegalArgumentException();
                int part = Integer.parseInt(parts[i]);
                if (part > 255) throw new IllegalArgumentException();
                bytes[i]=(byte)part;
            }
            return bytes;
        } catch (Exception e) { throw new IllegalArgumentException("Use a literal IPv4 or IPv6 address"); }
    }
    static String literal(String value) {
        try { return InetAddress.getByAddress(address(value)).getHostAddress(); }
        catch (Exception e) { throw new IllegalArgumentException("Invalid address"); }
    }
    static Scope parse(String value) {
        try {
            String[] parts=value.split("/",-1);
            if(parts.length!=2 || !parts[1].matches("0|[1-9][0-9]{0,2}")) throw new IllegalArgumentException();
            byte[] bytes=address(parts[0]); int prefix=Integer.parseInt(parts[1]);
            if(prefix<0 || prefix>bytes.length*8) throw new IllegalArgumentException();
            Scope scope=new Scope(bytes,prefix);
            if(!Arrays.equals(bytes,scope.mask(bytes))) throw new IllegalArgumentException();
            return scope;
        } catch(Exception e) { throw new IllegalArgumentException("Provide a canonical network CIDR"); }
    }
    byte[] mask(byte[] address) {
        byte[] result=address.clone();
        for(int i=0;i<result.length;i++) { int bits=Math.max(0,Math.min(8,prefix-i*8)); result[i]=(byte)(result[i] & (0xff << (8-bits))); }
        return result;
    }
    boolean contains(String value) { byte[] bytes=address(value); return bytes.length==network.length && Arrays.equals(network,mask(bytes)); }
}
