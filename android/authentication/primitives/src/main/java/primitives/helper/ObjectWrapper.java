/*
 * Copyright 2016 Max Kolhagen - TU Darmstadt, Germany
 * Released under GPLv3. See LICENSE.txt for details.
 */
package primitives.helper;

import android.os.Bundle;
import android.os.Parcel;
import android.os.Parcelable;

import java.io.Serializable;

/**
 * ObjectWrapper Wrapper object for an arbitrary object (Serializable, Parcelable).
 *
 *@author Max Kolhagen
 */
public class ObjectWrapper implements Parcelable {
    private static final String EXTRA_SERIALIZABLE = "primitives.helper.extra.SERIALIZABLE";
    private static final String EXTRA_PARCELABLE = "primitives.helper.extra.PARCELABLE";

    private Bundle bundle = null;

    private ObjectWrapper() {
        // hide
    }

    public ObjectWrapper(Serializable object) {
        this.bundle = new Bundle();
        this.bundle.putSerializable(EXTRA_SERIALIZABLE, object);
    }

    public ObjectWrapper(Parcelable object) {
        this.bundle = new Bundle();
        this.bundle.putParcelable(EXTRA_PARCELABLE, object);
    }

    public Object getObject() {
        if (this.bundle == null)
            return null;

        if (this.bundle.containsKey(EXTRA_SERIALIZABLE)) {
            return this.bundle.getSerializable(EXTRA_SERIALIZABLE);
        } else if (this.bundle.containsKey(EXTRA_PARCELABLE)) {
            return this.bundle.getParcelable(EXTRA_PARCELABLE);
        }

        return null;
    }

    public int describeContents() {
        return 0;
    }

    public void writeToParcel(Parcel out, int flags) {
        out.writeParcelable(this.bundle, flags);
    }

    public static final Parcelable.Creator<ObjectWrapper> CREATOR
            = new Parcelable.Creator<ObjectWrapper>() {
        public ObjectWrapper createFromParcel(Parcel in) {
            ObjectWrapper result = new ObjectWrapper();
            result.bundle = in.readParcelable(Bundle.class.getClassLoader());
            return result;
        }

        public ObjectWrapper[] newArray(int size) {
            return new ObjectWrapper[size];
        }
    };
}
