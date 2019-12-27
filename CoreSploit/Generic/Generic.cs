// Author: Ryan Cobb (@cobbr_io)
// Project: Coresploit (https://github.com/checkymander/CoreSploit)
// License: BSD 3-Clause

using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace CoreSploit.Generic
{
    /// <summary>
    /// GenericObjectResult for listing objects whose type is unknown at compile time.
    /// </summary>
    public sealed class GenericObjectResult : CoreSploitResult
    {
        public object Result { get; }
        protected internal override IList<CoreSploitResultProperty> ResultProperties
        {
            get
            {
                return new List<CoreSploitResultProperty>
                    {
                        new CoreSploitResultProperty
                        {
                            Name = this.Result.GetType().Name,
                            Value = this.Result
                        }
                    };
            }
        }

        public GenericObjectResult(object Result)
        {
            this.Result = Result;
        }
    }

    /// <summary>
    /// CoreSploitResultList extends the IList interface for CoreSploitResults to easily
    /// format a list of results from various CoreSploit functions.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class CoreSploitResultList<T> : IList<T> where T : CoreSploitResult
    {
        private List<T> Results { get; } = new List<T>();

        public int Count => Results.Count;
        public bool IsReadOnly => ((IList<T>)Results).IsReadOnly;


        private const int PROPERTY_SPACE = 3;

        /// <summary>
        /// Formats a CoreSploitResultList to a string similar to PowerShell's Format-List function.
        /// </summary>
        /// <returns>string</returns>
        public string FormatList()
        {
            return this.ToString();
        }

        private string FormatTable()
        {
            // TODO
            return "";
        }

        /// <summary>
        /// Formats a CoreSploitResultList as a string. Overrides ToString() for convenience.
        /// </summary>
        /// <returns>string</returns>
        public override string ToString()
        {
            if (this.Results.Count > 0)
            {
                StringBuilder labels = new StringBuilder();
                StringBuilder underlines = new StringBuilder();
                List<StringBuilder> rows = new List<StringBuilder>();
                for (int i = 0; i < this.Results.Count; i++)
                {
                    rows.Add(new StringBuilder());
                }
                for (int i = 0; i < this.Results[0].ResultProperties.Count; i++)
                {
                    labels.Append(this.Results[0].ResultProperties[i].Name);
                    underlines.Append(new string('-', this.Results[0].ResultProperties[i].Name.Length));
                    int maxproplen = 0;
                    for (int j = 0; j < rows.Count; j++)
                    {
                        CoreSploitResultProperty property = this.Results[j].ResultProperties[i];
                        string ValueString = property.Value.ToString();
                        rows[j].Append(ValueString);
                        if (maxproplen < ValueString.Length)
                        {
                            maxproplen = ValueString.Length;
                        }
                    }
                    if (i != this.Results[0].ResultProperties.Count - 1)
                    {
                        labels.Append(new string(' ', Math.Max(2, maxproplen + 2 - this.Results[0].ResultProperties[i].Name.Length)));
                        underlines.Append(new string(' ', Math.Max(2, maxproplen + 2 - this.Results[0].ResultProperties[i].Name.Length)));
                        for (int j = 0; j < rows.Count; j++)
                        {
                            CoreSploitResultProperty property = this.Results[j].ResultProperties[i];
                            string ValueString = property.Value.ToString();
                            rows[j].Append(new string(' ', Math.Max(this.Results[0].ResultProperties[i].Name.Length - ValueString.Length + 2, maxproplen - ValueString.Length + 2)));
                        }
                    }
                }
                labels.AppendLine();
                labels.Append(underlines.ToString());
                foreach (StringBuilder row in rows)
                {
                    labels.AppendLine();
                    labels.Append(row.ToString());
                }
                return labels.ToString();
            }
            return "";
        }

        public T this[int index] { get => Results[index]; set => Results[index] = value; }

        public IEnumerator<T> GetEnumerator()
        {
            return Results.Cast<T>().GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return Results.Cast<T>().GetEnumerator();
        }

        public int IndexOf(T item)
        {
            return Results.IndexOf(item);
        }

        public void Add(T t)
        {
            Results.Add(t);
        }

        public void AddRange(IEnumerable<T> range)
        {
            Results.AddRange(range);
        }

        public void Insert(int index, T item)
        {
            Results.Insert(index, item);
        }

        public void RemoveAt(int index)
        {
            Results.RemoveAt(index);
        }

        public void Clear()
        {
            Results.Clear();
        }

        public bool Contains(T item)
        {
            return Results.Contains(item);
        }

        public void CopyTo(T[] array, int arrayIndex)
        {
            Results.CopyTo(array, arrayIndex);
        }

        public bool Remove(T item)
        {
            return Results.Remove(item);
        }
    }

    /// <summary>
    /// Abstract class that represents a result from a CoreSploit function.
    /// </summary>
    public abstract class CoreSploitResult
    {
        protected internal abstract IList<CoreSploitResultProperty> ResultProperties { get; }
    }

    /// <summary>
    /// CoreSploitResultProperty represents a property that is a member of a CoreSploitResult's ResultProperties.
    /// </summary>
    public class CoreSploitResultProperty
    {
        public string Name { get; set; }
        public object Value { get; set; }
    }

    public enum Platform
    {
        x86,
        x64,
        IA64,
        Unknown
    }
}
