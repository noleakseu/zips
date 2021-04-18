package eu.noleaks.zips;

public enum Tags {
    Possessor("Possessor"),
    Title("Title"),
    Subject("Subject"),
    Keywords("Keywords"),
    Version("Version"),
    TimestampingAuthority("Timestamping-Authority"),
    SignedBy("Signed-By"),
    Timestamp("Timestamp");

    private final String attribute;

    Tags(String attribute) {
        this.attribute = attribute;
    }

    String getAttribute() {
        return attribute;
    }

    static Enum<Tags> nameOf(String value) {
        for (Tags tags : Tags.values()) {
            if (tags.getAttribute().equals(value)) {
                return tags;
            }
        }
        throw new IllegalArgumentException("No name for " + value);
    }
}